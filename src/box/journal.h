#ifndef TARANTOOL_JOURNAL_H_INCLUDED
#define TARANTOOL_JOURNAL_H_INCLUDED
/*
 * Copyright 2010-2017, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdint.h>
#include <stdbool.h>
#include "salad/stailq.h"
#include "fiber.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct xrow_header;
struct journal_entry;

typedef void (*journal_write_async_f)(struct journal_entry *entry);

enum {
	/** Entry didn't attempt a journal write. */
	JOURNAL_ENTRY_ERR_UNKNOWN = -1,
	/** Tried to be written, but something happened related to IO. */
	JOURNAL_ENTRY_ERR_IO = -2,
	/**
	 * Rollback because there is a not finished rollback of a previous
	 * entry.
	 */
	JOURNAL_ENTRY_ERR_CASCADE = -3,
	/** Rollback due to fiber waiting for WAL is cancelled. */
	JOURNAL_ENTRY_ERR_CANCELLED = -4,
	/**
	 * Anchor for the structs built on top of journal entry so as they
	 * could introduce their own unique errors. Set to a big value in
	 * advance.
	 */
	JOURNAL_ENTRY_ERR_MIN = -100,
};

/**
 * Convert a result of a journal entry write to an error installed into the
 * current diag.
 */
void
diag_set_journal_res_detailed(const char *file, unsigned line, int64_t res);

#define diag_set_journal_res(res)						\
	diag_set_journal_res_detailed(__FILE__, __LINE__, res)

/**
 * An entry for an abstract journal.
 * Simply put, a write ahead log request.
 *
 * In case of synchronous replication, this request will travel
 * first to a Raft leader before going to the local WAL.
 */
struct journal_entry {
	/** A helper to include requests into a FIFO queue. */
	struct stailq_entry fifo;
	/**
	 * On success, contains vclock signature of
	 * the committed transaction, on error is -1
	 */
	int64_t res;
	/**
	 * A journal entry completion callback argument.
	 */
	void *complete_data;
	/** Flags that should be set for the last entry row. */
	uint8_t flags;
	/**
	 * Asynchronous write completion function.
	 */
	journal_write_async_f write_async_cb;
	/**
	 * Approximate size of this request when encoded.
	 */
	size_t approx_len;
	/**
	 * Set to true when execution of a batch that contains this
	 * journal entry is completed.
	 */
	bool is_complete;
	/**
	 * Fiber which put the request in journal queue.
	 */
	struct fiber *fiber;
	/**
	 * The number of rows in the request.
	 */
	int n_rows;
	/**
	 * The rows.
	 */
	struct xrow_header *rows[];
};

struct region;

/**
 * Initialize a new journal entry.
 */
static inline void
journal_entry_create(struct journal_entry *entry, size_t n_rows,
		     size_t approx_len,
		     journal_write_async_f write_async_cb,
		     void *complete_data)
{
	entry->write_async_cb	= write_async_cb;
	entry->complete_data	= complete_data;
	entry->approx_len	= approx_len;
	entry->n_rows		= n_rows;
	entry->res		= JOURNAL_ENTRY_ERR_UNKNOWN;
	entry->flags		= 0;
	entry->is_complete = false;
	entry->fiber = NULL;
}

/**
 * Create a new journal entry.
 *
 * @return NULL if out of memory, fiber diagnostics area is set
 */
struct journal_entry *
journal_entry_new(size_t n_rows, struct region *region,
		  journal_write_async_f write_async_cb,
		  void *complete_data);

/**
 * Treat complete_data like a fiber pointer and wake it up when journal write is
 * done.
 */
void
journal_entry_fiber_wakeup_cb(struct journal_entry *entry);

struct journal_queue {
	/** Maximal size of entries enqueued in journal (in bytes). */
	int64_t max_size;
	/** Current approximate size of journal queue. */
	int64_t size;
	/** The requests waiting in journal queue. */
	struct stailq requests;
};

/** A single queue for all journal instances. */
extern struct journal_queue journal_queue;

/**
 * An API for an abstract journal for all transactions of this
 * instance, as well as for multiple instances in case of
 * synchronous replication.
 */
struct journal {
	/** Asynchronous write */
	int (*write_async)(struct journal *journal,
			   struct journal_entry *entry);
};

/** Wake the journal queue up. */
void
journal_queue_wakeup(void);

/** Yield until there's some space in the journal queue. */
int
journal_queue_wait(struct journal_entry *entry);

/** Flush journal queue. Next wal_sync() will sync flushed requests. */
int
journal_queue_flush(void);

/** Set maximal journal queue size in bytes. */
static inline void
journal_queue_set_max_size(int64_t size)
{
	journal_queue.max_size = size;
	journal_queue_wakeup();
}

/** Increase queue size on a new write request. */
static inline void
journal_queue_on_append(const struct journal_entry *entry)
{
	journal_queue.size += entry->approx_len;
}

/** Decrease queue size once write request is complete. */
static inline void
journal_queue_on_complete(const struct journal_entry *entry)
{
	journal_queue.size -= entry->approx_len;
	assert(journal_queue.size >= 0);
}

/** Rollback all txns waiting in queue. */
void
journal_queue_rollback(void);

/**
 * Complete asynchronous write.
 */
static inline void
journal_async_complete(struct journal_entry *entry)
{
	assert(entry->write_async_cb != NULL);

	entry->is_complete = true;

	journal_queue_on_complete(entry);

	entry->write_async_cb(entry);
}

/**
 * Depending on the step of recovery and instance configuration
 * points at a concrete implementation of the journal.
 */
extern struct journal *current_journal;

/** Write a single row in a blocking way. */
int
journal_write_row(struct xrow_header *row);

/** Checks whether journal_write_submit() call will yield. */
static inline bool
journal_queue_would_block(void)
{
	return journal_queue.size > journal_queue.max_size ||
	       !stailq_empty(&journal_queue.requests);
}

/**
 * Queue a single entry to the journal in asynchronous way.
 *
 * @return 0 if write was queued to a backend or -1 in case of an error.
 */
static inline int
journal_write_submit(struct journal_entry *entry)
{
	if (journal_queue_wait(entry) != 0)
		return -1;
	/*
	 * We cannot account entry after write. If journal is synchronous
	 * the journal_queue_on_complete() is called in write_async().
	 */
	journal_queue_on_append(entry);
	if (current_journal->write_async(current_journal, entry) != 0) {
		journal_queue_on_complete(entry);
		journal_queue_rollback();
		return -1;
	}
	return 0;
}

/** Write a single entry to the journal in synchronous way. */
static inline int
journal_write(struct journal_entry *entry)
{
	if (journal_write_submit(entry) != 0)
		return -1;
	while (!entry->is_complete)
		fiber_yield();
	return 0;
}

/**
 * Change the current implementation of the journaling API.
 * Happens during life cycle of an instance:
 *
 * 1. When recovering a snapshot, the log sequence numbers
 *    don't matter and are not used, transactions
 *    can be recovered in any order. A stub API simply
 *    returns 0 for every write request.
 *
 * 2. When recovering from the local write ahead
 * log, the LSN of each entry is already known. In this case,
 * the journal API should simply return the existing
 * log sequence numbers of records and do nothing else.
 *
 * 2. After recovery, in wal_mode = NONE, the implementation
 * fakes a WAL by using a simple counter to provide
 * log sequence numbers.
 *
 * 3. If the write ahead log is on, the WAL thread
 * is issuing the log sequence numbers.
 */
static inline void
journal_set(struct journal *new_journal)
{
	current_journal = new_journal;
}

static inline void
journal_create(struct journal *journal,
	       int (*write_async)(struct journal *journal,
				  struct journal_entry *entry))
{
	journal->write_async = write_async;
}

static inline bool
journal_is_initialized(struct journal *journal)
{
	return journal->write_async != NULL;
}

#if defined(__cplusplus)
} /* extern "C" */

#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_JOURNAL_H_INCLUDED */
