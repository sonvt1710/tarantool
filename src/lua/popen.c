/*
 * Copyright 2010-2020, Tarantool AUTHORS, please see AUTHORS file.
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

#include <sys/types.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <small/region.h>

#include "diag.h"
#include "core/popen.h"
#include "core/fiber.h"
#include "core/exception.h"
#include "tarantool_ev.h"

#include "lua/utils.h"
#include "lua/popen.h"

static const char *popen_handle_uname = "popen_handle";
static const char *popen_handle_closed_uname = "popen_handle_closed";

static const size_t POPEN_READ_BUF_SIZE = 4096;
static const double POPEN_WAIT_DELAY = 0.1;

/**
 * Helper map for transformation between std* popen.new() options
 * and popen backend engine flags.
 */
static const struct {
	unsigned int mask_devnull;
	unsigned int mask_close;
	unsigned int mask_pipe;
} pfd_map[POPEN_FLAG_FD_STDEND_BIT] = {
	{
		.mask_devnull	= POPEN_FLAG_FD_STDIN_DEVNULL,
		.mask_close	= POPEN_FLAG_FD_STDIN_CLOSE,
		.mask_pipe	= POPEN_FLAG_FD_STDIN,
	}, {
		.mask_devnull	= POPEN_FLAG_FD_STDOUT_DEVNULL,
		.mask_close	= POPEN_FLAG_FD_STDOUT_CLOSE,
		.mask_pipe	= POPEN_FLAG_FD_STDOUT,
	}, {
		.mask_devnull	= POPEN_FLAG_FD_STDERR_DEVNULL,
		.mask_close	= POPEN_FLAG_FD_STDERR_CLOSE,
		.mask_pipe	= POPEN_FLAG_FD_STDERR,
	},
};

/* {{{ Signals */

struct popen_lua_signal_def {
	const char *signame;
	int signo;
};

static struct popen_lua_signal_def popen_lua_signals[] =
{
#ifdef SIGHUP
	{"SIGHUP", SIGHUP},
#endif
#ifdef SIGINT
	{"SIGINT", SIGINT},
#endif
#ifdef SIGQUIT
	{"SIGQUIT", SIGQUIT},
#endif
#ifdef SIGILL
	{"SIGILL", SIGILL},
#endif
#ifdef SIGTRAP
	{"SIGTRAP", SIGTRAP},
#endif
#ifdef SIGABRT
	{"SIGABRT", SIGABRT},
#endif
#ifdef SIGIOT
	{"SIGIOT", SIGIOT},
#endif
#ifdef SIGBUS
	{"SIGBUS", SIGBUS},
#endif
#ifdef SIGFPE
	{"SIGFPE", SIGFPE},
#endif
#ifdef SIGKILL
	{"SIGKILL", SIGKILL},
#endif
#ifdef SIGUSR1
	{"SIGUSR1", SIGUSR1},
#endif
#ifdef SIGSEGV
	{"SIGSEGV", SIGSEGV},
#endif
#ifdef SIGUSR2
	{"SIGUSR2", SIGUSR2},
#endif
#ifdef SIGPIPE
	{"SIGPIPE", SIGPIPE},
#endif
#ifdef SIGALRM
	{"SIGALRM", SIGALRM},
#endif
#ifdef SIGTERM
	{"SIGTERM", SIGTERM},
#endif
#ifdef SIGSTKFLT
	{"SIGSTKFLT", SIGSTKFLT},
#endif
#ifdef SIGCHLD
	{"SIGCHLD", SIGCHLD},
#endif
#ifdef SIGCONT
	{"SIGCONT", SIGCONT},
#endif
#ifdef SIGSTOP
	{"SIGSTOP", SIGSTOP},
#endif
#ifdef SIGTSTP
	{"SIGTSTP", SIGTSTP},
#endif
#ifdef SIGTTIN
	{"SIGTTIN", SIGTTIN},
#endif
#ifdef SIGTTOU
	{"SIGTTOU", SIGTTOU},
#endif
#ifdef SIGURG
	{"SIGURG", SIGURG},
#endif
#ifdef SIGXCPU
	{"SIGXCPU", SIGXCPU},
#endif
#ifdef SIGXFSZ
	{"SIGXFSZ", SIGXFSZ},
#endif
#ifdef SIGVTALRM
	{"SIGVTALRM", SIGVTALRM},
#endif
#ifdef SIGPROF
	{"SIGPROF", SIGPROF},
#endif
#ifdef SIGWINCH
	{"SIGWINCH", SIGWINCH},
#endif
#ifdef SIGIO
	{"SIGIO", SIGIO},
#endif
#ifdef SIGPOLL
	{"SIGPOLL", SIGPOLL},
#endif
#ifdef SIGPWR
	{"SIGPWR", SIGPWR},
#endif
#ifdef SIGSYS
	{"SIGSYS", SIGSYS},
#endif
	{NULL, 0},
};

/* }}} */

/* {{{ Stream actions */

struct popen_lua_action_def {
	const char *name;
	const char *value;
	bool devnull;
	bool close;
	bool pipe;
};

#define POPEN_LUA_STREAM_INHERIT	"inherit"
#define POPEN_LUA_STREAM_DEVNULL	"devnull"
#define POPEN_LUA_STREAM_CLOSE		"close"
#define POPEN_LUA_STREAM_PIPE		"pipe"

static struct popen_lua_action_def popen_lua_actions[] = {
	{
		.name		= "INHERIT",
		.value		= POPEN_LUA_STREAM_INHERIT,
		.devnull	= false,
		.close		= false,
		.pipe		= false,
	},
	{
		.name		= "DEVNULL",
		.value		= POPEN_LUA_STREAM_DEVNULL,
		.devnull	= true,
		.close		= false,
		.pipe		= false,
	},
	{
		.name		= "CLOSE",
		.value		= POPEN_LUA_STREAM_CLOSE,
		.devnull	= false,
		.close		= true,
		.pipe		= false,
	},
	{
		.name		= "PIPE",
		.value		= POPEN_LUA_STREAM_PIPE,
		.devnull	= false,
		.close		= false,
		.pipe		= true,
	},
	{NULL, NULL, false, false, false},
};

/* }}} */

/* {{{ Process states */

struct popen_lua_state_def {
	const char *name;
	const char *value;
};

#define POPEN_LUA_STATE_ALIVE "alive"
#define POPEN_LUA_STATE_EXITED "exited"
#define POPEN_LUA_STATE_SIGNALED "signaled"

static struct popen_lua_state_def popen_lua_states[] = {
	{"ALIVE",	POPEN_LUA_STATE_ALIVE},
	{"EXITED",	POPEN_LUA_STATE_EXITED},
	{"SIGNALED",	POPEN_LUA_STATE_SIGNALED},
	{NULL, NULL},
};

/* }}} */

/* {{{ Lua stack push / pop helpers */

/**
 * Push popen handle into the Lua stack.
 *
 * Return 1 -- amount of pushed values.
 */
static int
luaT_push_popen_handle(struct lua_State *L, struct popen_handle *handle)
{
	*(struct popen_handle **)lua_newuserdata(L, sizeof(handle)) = handle;
	luaL_getmetatable(L, popen_handle_uname);
	lua_setmetatable(L, -2);
	return 1;
}

/**
 * Extract popen handle from the Lua stack.
 *
 * Return NULL in case of unexpected type.
 */
static struct popen_handle *
luaT_check_popen_handle(struct lua_State *L, int idx, bool *is_closed_ptr)
{
	struct popen_handle **handle_ptr =
		luaL_testudata(L, idx, popen_handle_uname);
	bool is_closed = false;

	if (handle_ptr == NULL) {
		handle_ptr = luaL_testudata(L, idx, popen_handle_closed_uname);
		is_closed = true;
	}

	if (handle_ptr == NULL)
		return NULL;
	assert(*handle_ptr != NULL);

	if (is_closed_ptr != NULL)
		*is_closed_ptr = is_closed;
	return *handle_ptr;
}

/**
 * Extract a string from the Lua stack.
 *
 * Return (const char *) if so, otherwise return NULL.
 *
 * Unlike luaL_checkstring() it accepts only a string and does not
 * accept a number.
 *
 * Unlike luaL_checkstring() it does not raise an error, but
 * returns NULL when a type is not what is excepted.
 */
static const char *
luaL_check_string_strict(struct lua_State *L, int idx, size_t *len_ptr)
{
	if (lua_type(L, idx) != LUA_TSTRING)
		return NULL;

	const char *res = lua_tolstring(L, idx, len_ptr);
	assert(res != NULL);
	return res;
}

/**
 * Extract a timeout value from the Lua stack.
 *
 * Return -1.0 when error occurs.
 */
static ev_tstamp
luaT_check_timeout(struct lua_State *L, int idx)
{
	if (lua_type(L, idx) == LUA_TNUMBER)
		return lua_tonumber(L, idx);
	/* FIXME: Support cdata<int64_t> and cdata<uint64_t>. */
	return -1.0;
}

/**
 * Helper for luaL_push_string_safe().
 */
static int
luaL_push_string_wrapper(struct lua_State *L)
{
	char *str = (char *)lua_topointer(L, 1);
	size_t len = lua_tointeger(L, 2);
	lua_pushlstring(L, str, len);
	return 1;
}

/**
 * Push a string to the Lua stack.
 *
 * Return 0 at success, -1 at failure and set a diag.
 *
 * Possible errors:
 *
 * - LuajitError ("not enough memory"): no memory space for the
 *   Lua string.
 */
static int
luaL_push_string_safe(struct lua_State *L, char *str, size_t len)
{
	lua_pushcfunction(L, luaL_push_string_wrapper);
	lua_pushlightuserdata(L, str);
	lua_pushinteger(L, len);
	return luaT_call(L, 2, 1);
}

/**
 * XXX
 */
static int
luaT_popen_push_stdX(struct lua_State *L, int fd, unsigned int flags)
{
	for (size_t i = 0; popen_lua_actions[i].name != NULL; ++i) {
		bool devnull	= (flags & pfd_map[fd].mask_devnull) != 0;
		bool close	= (flags & pfd_map[fd].mask_close) != 0;
		bool pipe	= (flags & pfd_map[fd].mask_pipe) != 0;

		if (devnull == popen_lua_actions[i].devnull &&
		    close   == popen_lua_actions[i].close &&
		    pipe    == popen_lua_actions[i].pipe) {
			lua_pushstring(L, popen_lua_actions[i].value);
			return 1;
		}
	}

	lua_pushliteral(L, "invalid");
	return 1;
}

/**
 * Push popen options as a Lua table.
 *
 * Environment information is not stored in a popen handle and so
 * missed here.
 */
static int
luaT_push_popen_opts(struct lua_State *L, unsigned int flags)
{
	lua_createtable(L, 0, 6);

	luaT_popen_push_stdX(L, STDIN_FILENO, flags);
	lua_setfield(L, -2, "stdin");

	luaT_popen_push_stdX(L, STDOUT_FILENO, flags);
	lua_setfield(L, -2, "stdout");

	luaT_popen_push_stdX(L, STDERR_FILENO, flags);
	lua_setfield(L, -2, "stderr");

	/* env is skipped */

	lua_pushboolean(L, (flags & POPEN_FLAG_SHELL) != 0);
	lua_setfield(L, -2, "shell");

	lua_pushboolean(L, (flags & POPEN_FLAG_SETSID) != 0);
	lua_setfield(L, -2, "setsid");

	lua_pushboolean(L, (flags & POPEN_FLAG_RESTORE_SIGNALS) != 0);
	lua_setfield(L, -2, "restore_signals");

	lua_pushboolean(L, (flags & POPEN_FLAG_GROUP_SIGNAL) != 0);
	lua_setfield(L, -2, "group_signal");

	lua_pushboolean(L, (flags & POPEN_FLAG_KEEP_CHILD) != 0);
	lua_setfield(L, -2, "keep_child");

	return 1;
}

/**
 * Like lua_replace(), but does not pop the value if idx == top.
 *
 * XXX: describe better
 */
static void
luaL_replace_safe(struct lua_State *L, int idx)
{
	/*
	 * lua_replace() on 'top' index copy a value to itself
	 * first and then pops it from the stack.
	 */
	/* XXX: what if idx > top? */
	if (lua_gettop(L) != idx)
		lua_replace(L, idx);
}

/**
 * Push a process status to the Lua stack as a table.
 *
 * Possible formats:
 *
 *     {
 *         state = popen.state.ALIVE ('alive'),
 *     }
 *
 *     {
 *         state = popen.state.EXITED ('exited'),
 *         exit_code = <number>,
 *     }
 *     {
 *         state = popen.state.SIGNALED ('signaled'),
 *         signo = <number>,
 *         signame = <string>,
 *     }
 *
 * @param state POPEN_STATE_{ALIVE,EXITED,SIGNALED}
 *
 * @param exit_code is exit code when the process is exited and a
 * signal number when a process is signaled.
 *
 * @see enum popen_states
 * @see popen_state()
 */
static int
luaT_popen_push_process_status(struct lua_State *L, int state, int exit_code)
{
	lua_createtable(L, 0, 3);

	switch (state) {
	case POPEN_STATE_ALIVE:
		lua_pushliteral(L, POPEN_LUA_STATE_ALIVE);
		lua_setfield(L, -2, "state");
		break;
	case POPEN_STATE_EXITED:
		lua_pushliteral(L, POPEN_LUA_STATE_EXITED);
		lua_setfield(L, -2, "state");
		lua_pushinteger(L, exit_code);
		lua_setfield(L, -2, "exit_code");
		break;
	case POPEN_STATE_SIGNALED:
		lua_pushliteral(L, POPEN_LUA_STATE_SIGNALED);
		lua_setfield(L, -2, "state");
		lua_pushinteger(L, exit_code);
		lua_setfield(L, -2, "signo");

		/*
		 * FIXME: Preallocate signo -> signal name
		 * mapping.
		 */
		const char *signame = "unknown";
		for (int i = 0; popen_lua_signals[i].signame != NULL; ++i) {
			if (popen_lua_signals[i].signo == exit_code)
				signame = popen_lua_signals[i].signame;
		}
		lua_pushstring(L, signame);
		lua_setfield(L, -2, "signame");

		break;
	default:
		unreachable();
	}

	return 1;
}

/* }}} */

/* {{{ Parse parameters */

/**
 * XXX
 */
static int
luaL_popen_handle_closed_error(struct lua_State *L)
{
	lua_pushnil(L);
	lua_pushliteral(L, "popen: attempt to operate on a closed handle");
	return 2;
}

/**
 * XXX
 */
static int
luaL_popen_new_usage(struct lua_State *L, int idx, const char *param,
		     const char *exp)
{
	static const char *usage =
		"popen.new: wrong parameter \"%s\": expected %s, got %s\n"
		"\n"
		"Usage: popen.new(\n"
		"    argv (table),\n"
		"    opts (table, optional):\n"
		"    {\n"
		"        stdin (string, optional) =\n"
		"            popen.stream.INHERIT or\n"
		"            popen.stream.DEVNULL or\n"
		"            popen.stream.CLOSE or\n"
		"            popen.stream.PIPE\n"
		"        stdout (string, optional) =\n"
		"            (same as stdin)\n"
		"        stderr (string, optional) =\n"
		"            (same as stdin)\n"
		"        env (table, optional),\n"
		"        shell (boolean, optional) = <...>,\n"
		"        setsid (boolean, optional) = <...>,\n"
		"        restore_signals (boolean, optional) = <...>,\n"
		"        group_signal (boolean, optional) = <...>,\n"
		"        keep_child (boolean, optional) = <...>,\n"
		"    }\n"
		")";
	const char *typename = idx == 0 ?
		"<unknown>" : lua_typename(L, lua_type(L, idx));
	return luaL_error(L, usage, param, exp, typename);
}

/**
 * XXX
 */
static int
luaL_popen_shell_usage(struct lua_State *L, int idx, const char *param,
		       const char *exp)
{
	static const char *usage =
		"popen.shell: wrong parameter \"%s\": expected %s, got %s\n"
		"\n"
		"Usage: popen.shell(\n"
		"    argv (table)),\n"
		"    mode (string, optional)) =\n"
		"        'r' or 'w' or 'rw'\n"
		")";
	const char *typename = idx == 0 ?
		"<unknown>" : lua_typename(L, lua_type(L, idx));
	return luaL_error(L, usage, param, exp, typename);
}

/**
 * XXX
 */
static void
luaL_popen_parse_stdX(struct lua_State *L, int idx, int fd,
		      unsigned int *flags_p)
{
	// XXX: rewrite luaL_popen_parse_stdX() to push an error
	// to the Lua stack in order to free argv / opts before
	// return

	const char *action;
	size_t action_len;
	if ((action = luaL_check_string_strict(L, idx, &action_len)) == NULL)
		luaL_popen_new_usage(L, idx, "opts.stdin", "string or nil");

	unsigned int flags = *flags_p;

	/* See popen_lua_actions. */
	if (strncmp(action, POPEN_LUA_STREAM_INHERIT, action_len) == 0) {
		flags &= ~pfd_map[fd].mask_devnull;
		flags &= ~pfd_map[fd].mask_close;
		flags &= ~pfd_map[fd].mask_pipe;
	} else if (strncmp(action, POPEN_LUA_STREAM_DEVNULL, action_len) == 0) {
		flags |= pfd_map[fd].mask_devnull;
		flags &= ~pfd_map[fd].mask_close;
		flags &= ~pfd_map[fd].mask_pipe;
	} else if (strncmp(action, POPEN_LUA_STREAM_CLOSE, action_len) == 0) {
		flags &= ~pfd_map[fd].mask_devnull;
		flags |= pfd_map[fd].mask_close;
		flags &= ~pfd_map[fd].mask_pipe;
	} else if (strncmp(action, POPEN_LUA_STREAM_PIPE, action_len) == 0) {
		flags &= ~pfd_map[fd].mask_devnull;
		flags &= ~pfd_map[fd].mask_close;
		flags |= pfd_map[fd].mask_pipe;
	} else {
		/* FIXME: Give better error message. */
		luaL_popen_new_usage(L, 0, "opts.std<...>", "<action>");
	}

	*flags_p = flags;
}

/**
 * XXX
 */
static char **
luaL_popen_parse_env(struct lua_State *L, int idx)
{
	if (lua_type(L, idx) != LUA_TTABLE) {
		luaL_popen_new_usage(L, idx, "opts.env", "table or nil");
		unreachable();
		return NULL;
	}

	size_t capacity = 256;
	char **env = malloc(capacity * sizeof(char *));
	size_t nr_env = 0;

	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		size_t key_len;
		size_t value_len;
		/* FIXME: Key should not contain '='. */
		/* FIXME: Key / value should not contain zero bytes. */
		const char *key = luaL_check_string_strict(L, -2, &key_len);
		const char *value = luaL_check_string_strict(L, -1, &value_len);
		if (key == NULL || value == NULL)
			goto err;
		/* XXX: Use tt_snprintf() or SNPRINTF. */
		size_t entry_len = key_len + value_len + 1;
		char *entry = malloc(entry_len + 1);
		int rc = snprintf("%s=%s", entry_len + 1, key, value);
		assert(rc >= 0);
		/* Reserve space for the next entry and NULL. */
		// XXX: check it
		if (capacity < nr_env + 1) {
			capacity *= 2;
			env = realloc(env, capacity * sizeof(char *));
		}
		env[nr_env++] = entry;
		lua_pop(L, 1);
	}
	env[nr_env] = NULL;
	return env;
err:
	for (size_t i = 0; i < nr_env; ++i)
		free(env[i]);
	free(env);
	// XXX: give better error
	luaL_popen_new_usage(L, idx, "opts.env",
			     "{[<string>] = <string>, ...}");
	unreachable();
	return NULL;
}

/**
 * XXX
 */
static void
luaL_popen_parse_opts(struct lua_State *L, int idx, struct popen_opts *opts)
{
	/* Default flags: close everything. */
	opts->flags = POPEN_FLAG_NONE		|
		POPEN_FLAG_FD_STDIN_CLOSE	|
		POPEN_FLAG_FD_STDOUT_CLOSE	|
		POPEN_FLAG_FD_STDERR_CLOSE	|
		POPEN_FLAG_CLOSE_FDS		|
		POPEN_FLAG_RESTORE_SIGNALS;

	/* Parse options. */
	if (lua_type(L, idx) == LUA_TTABLE) {
		lua_getfield(L, idx, "stdin");
		if (! lua_isnil(L, -1)) {
			luaL_popen_parse_stdX(L, -1, STDIN_FILENO,
					      &opts->flags);
		}
		lua_pop(L, 1);

		lua_getfield(L, idx, "stdout");
		if (! lua_isnil(L, -1))
			luaL_popen_parse_stdX(L, -1, STDOUT_FILENO,
					      &opts->flags);
		lua_pop(L, 1);

		lua_getfield(L, idx, "stderr");
		if (! lua_isnil(L, -1))
			luaL_popen_parse_stdX(L, -1, STDERR_FILENO,
					      &opts->flags);
		lua_pop(L, 1);

		lua_getfield(L, idx, "env");
		if (! lua_isnil(L, -1)) {
			opts->env = luaL_popen_parse_env(L, -1);
			assert(opts->env != NULL);
		}
		lua_pop(L, 1);

		lua_getfield(L, idx, "shell");
		if (! lua_isnil(L, -1)) {
			if (lua_type(L, -1) != LUA_TBOOLEAN)
				luaL_popen_new_usage(L, -1, "opts.shell",
						     "boolean or nil");
			if (lua_toboolean(L, -1) == 0)
				opts->flags &= ~POPEN_FLAG_SHELL;
			else
				opts->flags |= POPEN_FLAG_SHELL;
		}
		lua_pop(L, 1);

		lua_getfield(L, idx, "setsid");
		if (! lua_isnil(L, -1)) {
			if (lua_type(L, -1) != LUA_TBOOLEAN)
				luaL_popen_new_usage(L, -1, "opts.setsid",
						     "boolean or nil");
			if (lua_toboolean(L, -1) == 0)
				opts->flags &= ~POPEN_FLAG_SETSID;
			else
				opts->flags |= POPEN_FLAG_SETSID;
		}
		lua_pop(L, 1);

		lua_getfield(L, idx, "restore_signals");
		if (! lua_isnil(L, -1)) {
			if (lua_type(L, -1) != LUA_TBOOLEAN)
				luaL_popen_new_usage(L, -1,
						     "opts.restore_signals",
						     "boolean or nil");
			if (lua_toboolean(L, -1) == 0)
				opts->flags &= ~POPEN_FLAG_RESTORE_SIGNALS;
			else
				opts->flags |= POPEN_FLAG_RESTORE_SIGNALS;
		}
		lua_pop(L, 1);

		lua_getfield(L, idx, "group_signal");
		if (! lua_isnil(L, -1)) {
			if (lua_type(L, -1) != LUA_TBOOLEAN)
				luaL_popen_new_usage(L, -1, "opts.group_signal",
						     "boolean or nil");
			if (lua_toboolean(L, -1) == 0)
				opts->flags &= ~POPEN_FLAG_GROUP_SIGNAL;
			else
				opts->flags |= POPEN_FLAG_GROUP_SIGNAL;
		}
		lua_pop(L, 1);

		lua_getfield(L, idx, "keep_child");
		if (! lua_isnil(L, -1)) {
			if (lua_type(L, -1) != LUA_TBOOLEAN)
				luaL_popen_new_usage(L, -1, "opts.keep_child",
						     "boolean or nil");
			if (lua_toboolean(L, -1) == 0)
				opts->flags &= ~POPEN_FLAG_KEEP_CHILD;
			else
				opts->flags |= POPEN_FLAG_KEEP_CHILD;
		}
		lua_pop(L, 1);
	}
}

/**
 * XXX
 */
static void
luaL_popen_parse_argv(struct lua_State *L, int idx, struct popen_opts *opts)
{
	size_t argv_len = lua_objlen(L, idx);
	/*
	 * argv array should contain NULL element at the
	 * end and probably "sh", "-c" at the start.
	 */
	opts->nr_argv = argv_len + 1;
	if (opts->flags & POPEN_FLAG_SHELL)
		opts->nr_argv += 2;
	/* FIXME: Use region_alloc(). */
	opts->argv = malloc(sizeof(char *) * opts->nr_argv);
	const char **to = (const char **)opts->argv;
	if (opts->flags & POPEN_FLAG_SHELL) {
		opts->argv[0] = NULL;
		opts->argv[1] = NULL;
		to += 2;
	}

	for (size_t i = 0; i < argv_len; ++i) {
		lua_rawgeti(L, idx, i + 1);
		const char *arg;
		if ((arg = luaL_check_string_strict(L, -1, NULL)) == NULL) {
			free(opts->argv);
			luaL_popen_new_usage(L, 0, "argv[i]", "string");
		}
		*(to++) = arg;
		lua_pop(L, 1);
	}
	*to = NULL;
}

/**
 * XXX
 */
static void
luaL_popen_parse_mode(struct lua_State *L, int idx)
{
	if (lua_type(L, idx) != LUA_TSTRING &&
	    lua_type(L, idx) != LUA_TNONE &&
	    lua_type(L, idx) != LUA_TNIL)
		luaL_popen_shell_usage(L, idx, "mode", "string or nil");

	/*
	 * Create options table for popen.new().
	 *
	 * Preallocate space for shell, setsid, group_signal and
	 * std{in,out,err} options.
	 */
	lua_createtable(L, 0, 5);

	lua_pushboolean(L, true);
	lua_setfield(L, -2, "shell");

	lua_pushboolean(L, true);
	lua_setfield(L, -2, "setsid");

	lua_pushboolean(L, true);
	lua_setfield(L, -2, "group_signal");

	/*
	 * When mode is nil, left std* params default, which means
	 * to close the file descriptiors in a child process.
	 */
	if (lua_isnoneornil(L, idx))
		return;

	size_t mode_len;
	const char *mode = lua_tolstring(L, idx, &mode_len);
	for (size_t i = 0; i < mode_len; ++i) {
		switch (mode[i]) {
		case 'r':
			lua_pushstring(L, POPEN_LUA_STREAM_PIPE);
			lua_setfield(L, -2, "stdout");

			lua_pushstring(L, POPEN_LUA_STREAM_PIPE);
			lua_setfield(L, -2, "stderr");
			break;
		case 'w':
			lua_pushstring(L, POPEN_LUA_STREAM_PIPE);
			lua_setfield(L, -2, "stdin");
			break;
		default:
			luaL_popen_shell_usage(L, 0, "mode",
					       "'r' | 'w' | 'rw'");
		}
	}
}

/* }}} */

/* {{{ Lua API functions and methods */

/**
 * Creates a new popen handle and run a command.
 *
 * @command:	a command to run
 * @flags:	popen_flag_bits
 *
 * Returns pair @handle = data, @err = nil on success,
 * @handle = nil, err ~= nil on error.
 */
static int
lbox_popen_new(struct lua_State *L)
{
	if (lua_type(L, 1) != LUA_TTABLE)
		return luaL_popen_new_usage(L, 1, "argv", "table");
	else if (lua_type(L, 2) != LUA_TTABLE &&
		 lua_type(L, 2) != LUA_TNONE &&
		 lua_type(L, 2) != LUA_TNIL)
		return luaL_popen_new_usage(L, 2, "opts", "table or nil");

	struct popen_opts opts = {};
	luaL_popen_parse_opts(L, 2, &opts);
	luaL_popen_parse_argv(L, 1, &opts);

	struct popen_handle *handle = popen_new(&opts);

	free(opts.argv);
	if (opts.env != NULL) {
		for (size_t i = 0; opts.env[i] != NULL; ++i)
			free(opts.env[i]);
		free(opts.env);
	}

	if (handle == NULL)
		return luaT_push_nil_and_error(L);

	luaT_push_popen_handle(L, handle);
	return 1;
}

/**
 * XXX
 */
static int
lbox_popen_shell(struct lua_State *L)
{
	if (lua_type(L, 1) != LUA_TSTRING)
		return luaL_popen_shell_usage(L, 1, "command", "string");

	/* Create argv table for popen.new(). */
	lua_createtable(L, 1, 0);
	/* argv[1] = command */
	lua_pushvalue(L, 1);
	lua_rawseti(L, -2, 1);
	/* select(1, ...) == argv */
	luaL_replace_safe(L, 1);

	/* opts = parse_mode(mode) */
	luaL_popen_parse_mode(L, 2);
	/* select(2, ...) == opts */
	luaL_replace_safe(L, 2);

	return lbox_popen_new(L);
}

/**
 * Send signal to a child process.
 *
 * @handle:	a handle carries child process to terminate
 * @signo:	signal number to send
 *
 * Returns true if signal is sent.
 */
static int
lbox_popen_signal(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;
	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL ||
	    !lua_isnumber(L, 2))
		return luaL_error(L, "Bad params, use: ph:signal(signo)");
	if (is_closed)
		return luaL_popen_handle_closed_error(L);

	int signo = lua_tonumber(L, 2);

	if (popen_send_signal(handle, signo) != 0)
		return luaT_push_nil_and_error(L);

	lua_pushboolean(L, true);
	return 1;
}

/**
 * XXX
 */
static int
lbox_popen_terminate(struct lua_State *L)
{
	/*
	 * XXX: Rewrite it using common helper with signo and
	 * func_name parameters?
	 *
	 * It will allow to give proper function name in an error
	 * message in case of a failure.
	 */
	lua_pushinteger(L, SIGTERM);
	luaL_replace_safe(L, 2);
	return lbox_popen_signal(L);
}

/**
 * XXX
 */
static int
lbox_popen_kill(struct lua_State *L)
{
	/*
	 * XXX: Rewrite it using common helper with signo and
	 * func_name parameters?
	 *
	 * It will allow to give proper function name in an error
	 * message in case of a failure.
	 */
	lua_pushinteger(L, SIGKILL);
	luaL_replace_safe(L, 2);
	return lbox_popen_signal(L);
}

/**
 * XXX
 *
 * FIXME: Use trigger or fiber conds to sleep and wake up.
 *
 * FIXME: Add timeout option: ph:wait({timeout = <...>})
 */
static int
lbox_popen_wait(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;
	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL)
		return luaL_error(L, "Bad params, use: ph:wait()");
	if (is_closed)
		return luaL_popen_handle_closed_error(L);

	int state;
	int exit_code;

	while (true) {
		popen_state(handle, &state, &exit_code);
		if (state != POPEN_STATE_ALIVE)
			break;
		fiber_sleep(POPEN_WAIT_DELAY);
	}

	return luaT_popen_push_process_status(L, state, exit_code);
}

/**
 * Read data from a child peer.
 *
 * @handle:	handle of a child process
 * @opts:	an options table
 * - @stdout:	whether to read from stdout, boolean
 * - @stderr:	whether to read from stderr, boolean
 * - @timeout:	time quota in seconds
 *
 * Raise an error on incorrect parameters or when the fiber is
 * cancelled.
 *
 * Returns a string on success, an empty string at EOF.
 *
 * Returns `nil, err` on a failure.
 *
 * @see popen_read_timeout() for possible errors. Aside of those
 * errors the following may occur:
 *
 * - OutOfMemory: no memory space for a buffer to read into.
 * - LuajitError ("not enough memory"): no memory space for the
 *   Lua string.
 */
static int
lbox_popen_read(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;
	unsigned int flags = POPEN_FLAG_NONE;
	ev_tstamp timeout = TIMEOUT_INFINITY;

	/* Extract handle. */
	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL)
		goto usage;
	if (is_closed)
		return luaL_popen_handle_closed_error(L);

	/* Extract options. */
	if (!lua_isnoneornil(L, 2)) {
		if (lua_type(L, 2) != LUA_TTABLE)
			goto usage;

		lua_getfield(L, 2, "stdout");
		if (!lua_isnil(L, -1)) {
			if (lua_type(L, -1) == LUA_TBOOLEAN)
				flags |= POPEN_FLAG_FD_STDOUT;
			else
				goto usage;
		}
		lua_pop(L, 1);

		lua_getfield(L, 2, "stderr");
		if (!lua_isnil(L, -1)) {
			if (lua_type(L, -1) == LUA_TBOOLEAN)
				flags |= POPEN_FLAG_FD_STDERR;
			else
				goto usage;
		}
		lua_pop(L, 1);

		lua_getfield(L, 2, "timeout");
		if (!lua_isnil(L, -1) &&
		    (timeout = luaT_check_timeout(L, -1)) < 0.0)
			goto usage;
		lua_pop(L, 1);
	}

	/* Read from stdout by default. */
	if (!(flags & (POPEN_FLAG_FD_STDOUT | POPEN_FLAG_FD_STDERR)))
		flags |= POPEN_FLAG_FD_STDOUT;

	char *buf = region_alloc(&fiber()->gc, POPEN_READ_BUF_SIZE);
	if (buf == NULL) {
		diag_set(OutOfMemory, POPEN_READ_BUF_SIZE, "region_alloc",
			 "read buffer");
		return luaT_push_nil_and_error(L);
	}

	ssize_t rc = popen_read_timeout(handle, buf, POPEN_READ_BUF_SIZE, flags,
					timeout);
	if (rc < 0) {
		fiber_gc();
		struct error *e = diag_last_error(diag_get());
		if (e->type == &type_IllegalParams ||
		    e->type == &type_FiberIsCancelled)
			return luaT_error(L);
		return luaT_push_nil_and_error(L);
	}

	if (luaL_push_string_safe(L, buf, rc) != 0) {
		fiber_gc();
		return luaT_push_nil_and_error(L);
	}
	fiber_gc();
	return 1;

usage:
	return luaL_error(L, "Bad params, use: ph:read([{"
			  "stdout = <boolean>, "
			  "stderr = <boolean>, "
			  "timeout = <number>}])");
}

/**
 * Write data to a child peer.
 *
 * @handle:	a handle of a child process
 * @str:	a string to write
 * @opts:	an options table
 * - @timeout:	time quota in seconds
 *
 * Raise an error on incorrect parameters or when the fiber is
 * cancelled.
 *
 * Returns `true` on success, `nil, err` on a failure.
 *
 * @see popen_write_timeout() for possible errors.
 */
static int
lbox_popen_write(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;
	const char *str;
	size_t len;
	ev_tstamp timeout = TIMEOUT_INFINITY;

	/* Extract handle and string to write. */
	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL ||
	    (str = luaL_check_string_strict(L, 2, &len)) == NULL)
		goto usage;
	if (is_closed)
		return luaL_popen_handle_closed_error(L);

	/* Extract options. */
	if (!lua_isnoneornil(L, 3)) {
		if (lua_type(L, 3) != LUA_TTABLE)
			goto usage;

		lua_getfield(L, 3, "timeout");
		if (!lua_isnil(L, -1) &&
		    (timeout = luaT_check_timeout(L, -1)) < 0.0)
			goto usage;
		lua_pop(L, 1);
	}

	unsigned int flags = POPEN_FLAG_FD_STDIN;
	ssize_t rc = popen_write_timeout(handle, str, len, flags, timeout);
	assert(rc < 0 || rc == (ssize_t)len);
	if (rc < 0) {
		struct error *e = diag_last_error(diag_get());
		if (e->type == &type_IllegalParams ||
		    e->type == &type_FiberIsCancelled)
			return luaT_error(L);
		return luaT_push_nil_and_error(L);
	}
	lua_pushboolean(L, true);
	return 1;

usage:
	return luaL_error(L, "Bad params, use: ph:write(str[, {"
			  "timeout = <number>}])");
}

/**
 * Return information about popen handle.
 *
 * @handle:	a handle of a child process
 *
 * Returns a @table ~= nil, @err = nil on success,
 * @table = nil, @err ~= nil on error.
 */
static int
lbox_popen_info(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;

	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL)
		return luaL_error(L, "Bad params, use: ph:info()");
	if (is_closed)
		return luaL_popen_handle_closed_error(L);

	struct popen_stat st = {};

	popen_stat(handle, &st);

	lua_createtable(L, 0, 4);

	if (st.pid >= 0) {
		lua_pushinteger(L, st.pid);
		lua_setfield(L, -2, "pid");
	}

	lua_pushstring(L, popen_command(handle));
	lua_setfield(L, -2, "command");

	luaT_push_popen_opts(L, st.flags);
	lua_setfield(L, -2, "opts");

	int state;
	int exit_code;
	popen_state(handle, &state, &exit_code);
	assert(state < POPEN_STATE_MAX);
	luaT_popen_push_process_status(L, state, exit_code);
	lua_setfield(L, -2, "status");

	return 1;
}

/**
 * Close a popen handle
 *
 * @handle:	a handle to close
 *
 * If there is a running child it get killed first.
 *
 * Returns true if a handle is closed, nil, err otherwise.
 */
static int
lbox_popen_close(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;
	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL)
		return luaL_error(L, "Bad params, use: ph:close()");

	/* Do nothing on a closed handle. */
	if (is_closed) {
		lua_pushboolean(L, true);
		return 1;
	}

	if (popen_delete(handle) != 0)
		return luaT_push_nil_and_error(L);

	/*
	 * The handle is freed. Remove the GC handler to don't
	 * free it twice.
	 */
	luaL_getmetatable(L, popen_handle_closed_uname);
	lua_setmetatable(L, 1);

	lua_pushboolean(L, true);
	return 1;
}

/**
 * Get info from a handle.
 */
static int
lbox_popen_index(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;
	const char *key;

	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL ||
	    (key = luaL_check_string_strict(L, 2, NULL)) == NULL)
		return luaL_error(L, "Bad params, use __index(ph, <string>)");

	/* Get a value from the metatable. */
	lua_getmetatable(L, 1);
	lua_pushvalue(L, 2);
	lua_rawget(L, -2);
	if (! lua_isnil(L, -1))
		return 1;

	if (is_closed)
		return luaL_error(L, "Attempt to index closed popen handle");

	if (strcmp(key, "pid") == 0) {
		if (handle->pid >= 0)
			lua_pushinteger(L, handle->pid);
		else
			lua_pushnil(L);
		return 1;
	}

	if (strcmp(key, "command") == 0) {
		lua_pushstring(L, popen_command(handle));
		return 1;
	}

	if (strcmp(key, "opts") == 0) {
		luaT_push_popen_opts(L, handle->flags);
		return 1;
	}

	if (strcmp(key, "status") == 0) {
		int state;
		int exit_code;
		popen_state(handle, &state, &exit_code);
		return luaT_popen_push_process_status(L, state, exit_code);
	}

	lua_pushnil(L);
	return 1;
}

/**
 * XXX
 */
static int
lbox_popen_serialize(struct lua_State *L)
{
	struct popen_handle *handle;
	bool is_closed;

	if ((handle = luaT_check_popen_handle(L, 1, &is_closed)) == NULL)
		return luaL_error(L, "Bad params, use: __serialize(ph)");

	if (is_closed) {
		lua_pushliteral(L, "<closed popen handle>");
		return 1;
	}

	return lbox_popen_info(L);
}

/**
 * Lua GC handler, which free popen handle resources.
 *
 * @handle:	a handle to free
 *
 * Kills a child if there is one.
 */
static int
lbox_popen_gc(struct lua_State *L)
{
	bool is_closed;
	struct popen_handle *handle = luaT_check_popen_handle(L, 1, &is_closed);
	assert(!is_closed);
	assert(handle != NULL);
	popen_delete(handle);
	return 0;
}

/* }}} */

/**
 * Create popen functions and methods.
 */
void
tarantool_lua_popen_init(struct lua_State *L)
{
	/* Popen module methods. */
	static const struct luaL_Reg popen_methods[] = {
		{"new",		lbox_popen_new,		},
		{"shell",	lbox_popen_shell,	},
		{NULL, NULL},
	};
	luaL_register_module(L, "popen", popen_methods);

	/* Popen handle methods and metamethods. */
	static const struct luaL_Reg popen_handle_methods[] = {
		{"signal",		lbox_popen_signal,	},
		{"terminate",		lbox_popen_terminate,	},
		{"kill",		lbox_popen_kill,	},
		{"wait",		lbox_popen_wait,	},
		{"read",		lbox_popen_read,	},
		{"write",		lbox_popen_write,	},
		{"info",		lbox_popen_info,	},
		{"close",		lbox_popen_close,	},
		{"__index",		lbox_popen_index	},
		{"__serialize",		lbox_popen_serialize	},
		{"__gc",		lbox_popen_gc		},
		{NULL, NULL},
	};
	luaL_register_type(L, popen_handle_uname, popen_handle_methods);

	/*
	 * Closed popen handle methods and metamethods.
	 *
	 * No __gc metamethod: all resources are already
	 * collected.
	 */
	static const struct luaL_Reg popen_handle_closed_methods[] = {
		{"signal",		lbox_popen_signal,	},
		{"terminate",		lbox_popen_terminate,	},
		{"kill",		lbox_popen_kill,	},
		{"wait",		lbox_popen_wait,	},
		{"read",		lbox_popen_read,	},
		{"write",		lbox_popen_write,	},
		{"info",		lbox_popen_info,	},
		{"close",		lbox_popen_close,	},
		{"__index",		lbox_popen_index	},
		{"__serialize",		lbox_popen_serialize	},
		{NULL, NULL},
	};
	luaL_register_type(L, popen_handle_closed_uname,
			   popen_handle_closed_methods);

	/* Signals. */
	lua_newtable(L);
	for (int i = 0; popen_lua_signals[i].signame != NULL; ++i) {
		lua_pushinteger(L, popen_lua_signals[i].signo);
		lua_setfield(L, -2, popen_lua_signals[i].signame);
	}
	lua_setfield(L, -2, "signal");

	/* Stream actions. */
	lua_newtable(L);
	for (int i = 0; popen_lua_actions[i].name != NULL; ++i) {
		lua_pushstring(L, popen_lua_actions[i].value);
		lua_setfield(L, -2, popen_lua_actions[i].name);
	}
	lua_setfield(L, -2, "stream");

	/* Process states. */
	lua_newtable(L);
	for (int i = 0; popen_lua_states[i].name != NULL; ++i) {
		lua_pushstring(L, popen_lua_states[i].value);
		lua_setfield(L, -2, popen_lua_states[i].name);
	}
	lua_setfield(L, -2, "state");
}
