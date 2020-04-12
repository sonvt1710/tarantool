#ifndef INCLUDES_TARANTOOL_BOX_PORT_H
#define INCLUDES_TARANTOOL_BOX_PORT_H
/*
 * Copyright 2010-2016, Tarantool AUTHORS, please see AUTHORS file.
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
#include "trivia/util.h"
#include <port.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct tuple;

struct port_tuple_entry {
	struct port_tuple_entry *next;
	struct tuple *tuple;
};

/**
 * Port implementation used for storing tuples.
 */
struct port_tuple {
	const struct port_vtab *vtab;
	int size;
	struct port_tuple_entry *first;
	struct port_tuple_entry *last;
	struct port_tuple_entry first_entry;
};
static_assert(sizeof(struct port_tuple) <= sizeof(struct port),
	      "sizeof(struct port_tuple) must be <= sizeof(struct port)");

extern const struct port_vtab port_tuple_vtab;

/**
 * Convert an abstract port instance to a tuple port.
 */
static inline struct port_tuple *
port_tuple(struct port *port)
{
	return (struct port_tuple *)port;
}

/**
 * Create a port for storing tuples.
 */
void
port_tuple_create(struct port *port);

/**
 * Append a tuple to a port.
 */
int
port_tuple_add(struct port *port, struct tuple *tuple);

/** Port implementation used for storing raw data. */
struct port_msgpack {
	const struct port_vtab *vtab;
	const char *data;
	uint32_t data_sz;
	/**
	 * Buffer for dump_plain() function. It is created during
	 * dump on demand and is deleted together with the port.
	 */
	char *plain;
};

static_assert(sizeof(struct port_msgpack) <= sizeof(struct port),
	      "sizeof(struct port_msgpack) must be <= sizeof(struct port)");

/** Initialize a port to dump raw data. */
void
port_msgpack_create(struct port *port, const char *data, uint32_t data_sz);

/** Destroy a MessagePack port. */
void
port_msgpack_destroy(struct port *base);

/**
 * Set plain text version of data in the given port. It is copied.
 */
int
port_msgpack_set_plain(struct port *base, const char *plain, uint32_t len);

/** Port for storing the result of a Lua CALL/EVAL. */
struct port_lua {
	const struct port_vtab *vtab;
	/** Lua state that stores the result. */
	struct lua_State *L;
	/** Reference to L in tarantool_L. */
	int ref;
	/** Number of entries dumped to the port. */
	int size;
};

static_assert(sizeof(struct port_lua) <= sizeof(struct port),
	      "sizeof(struct port_lua) must be <= sizeof(struct port)");

/** Initialize a port to dump from Lua. */
void
port_lua_create(struct port *port, struct lua_State *L);

struct sql_value;

/** Port implementation used with vdbe memory variables. */
struct port_vdbemem {
    const struct port_vtab *vtab;
    struct sql_value *mem;
    uint32_t mem_count;
};

static_assert(sizeof(struct port_vdbemem) <= sizeof(struct port),
	      "sizeof(struct port_vdbemem) must be <= sizeof(struct port)");

/** Initialize a port to dump data in sql vdbe memory. */
void
port_vdbemem_create(struct port *base, struct sql_value *mem,
		    uint32_t mem_count);

void
port_init(void);

void
port_free(void);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined __cplusplus */

#endif /* INCLUDES_TARANTOOL_BOX_PORT_H */
