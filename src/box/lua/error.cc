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
#include "box/lua/error.h"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
} /* extern "C" */

#include <fiber.h>
#include <errinj.h>

#include "lua/utils.h"
#include "box/error.h"

struct error_args {
	uint32_t code;
	const char *reason;
	const char *custom;
	bool tb_mode;
	bool tb_parsed;
};

static int
luaT_error_parse_args(struct lua_State *L, int top_base,
		      struct error_args *args)
{
	int top = lua_gettop(L);
	int top_type = lua_type(L, top_base);
	if (top >= top_base &&
	    (top_type == LUA_TNUMBER || top_type == LUA_TSTRING)) {
		if (top_type == LUA_TNUMBER) {
			args->code = lua_tonumber(L, top_base);
		} else if (top_type == LUA_TSTRING) {
			args->code = ER_CUSTOM_ERROR;
			args->custom = lua_tostring(L, top_base);
		} else {
			return -1;
		}
		args->reason = tnt_errcode_desc(args->code);
		if (top > top_base) {
			/* Call string.format(reason, ...) to format message */
			lua_getglobal(L, "string");
			if (lua_isnil(L, -1))
				return 0;
			lua_getfield(L, -1, "format");
			if (lua_isnil(L, -1))
				return 0;
			lua_pushstring(L, args->reason);
			for (int i = top_base + 1; i <= top; i++)
				lua_pushvalue(L, i);
			lua_call(L, top - top_base + 1, 1);
			args->reason = lua_tostring(L, -1);
		} else if (strchr(args->reason, '%') != NULL) {
			/* Missing arguments to format string */
			return -1;
		}
	} else if (top == top_base && top_type == LUA_TTABLE) {
		lua_getfield(L, top_base, "code");
		if (lua_isnil(L, -1) == 0)
			args->code = lua_tonumber(L, -1);
		lua_pop(L, 1);
		lua_getfield(L, top_base, "reason");
		if (lua_isnil(L, -1) == 0)
			args->reason = lua_tostring(L, -1);
		lua_pop(L, 1);
		lua_getfield(L, top_base, "type");
		if (lua_isnil(L, -1) == 0)
			args->custom = lua_tostring(L, -1);
		lua_pop(L, 1);
		lua_getfield(L, top_base, "traceback");
		if (lua_isboolean(L, -1)) {
			args->tb_parsed = true;
			args->tb_mode = lua_toboolean(L, -1);
		}
		lua_pop(L, -1);
	} else {
		return -1;
	}

	return 0;
}

/**
 * Parse Lua arguments (they can come as single table
 * f({code : number, reason : string}) or as separate members
 * f(code, reason)) and construct struct error with given values.
 * In case one of arguments is missing its corresponding field
 * in struct error is filled with default value.
 */
static struct error *
luaT_error_create(lua_State *L, int top_base)
{
	struct error_args args;
	args.code = UINT32_MAX;
	args.reason = NULL;
	args.custom = NULL;
	args.tb_mode = false;
	args.tb_parsed = false;

	if (luaT_error_parse_args(L, top_base, &args) != 0) {
		return NULL;
	}

	if (args.reason == NULL)
		args.reason = "";

	const char *file = "";
	unsigned line = 0;
	lua_Debug info;
	if (lua_getstack(L, 1, &info) && lua_getinfo(L, "Sl", &info)) {
		if (*info.short_src) {
			file = info.short_src;
		} else if (*info.source) {
			file = info.source;
		} else {
			file = "eval";
		}
		line = info.currentline;
	}

	struct error *err = NULL;
	if (args.custom) {
		err = box_custom_error_new(file, line, args.custom,
					   "%s", args.reason);
	} else {
		err = box_error_new(file, line, args.code, "%s", args.reason);
	}

	if (args.tb_parsed)
		err->traceback_mode = args.tb_mode;

	return err;
}

static int
luaT_error_call(lua_State *L)
{
	if (lua_gettop(L) <= 1) {
		/* Re-throw saved exceptions if any. */
		if (box_error_last())
			return luaT_error(L);
		return 0;
	}
	struct error *e = NULL;
	if (lua_gettop(L) == 2) {
		e = luaL_iserror(L, 2);
		if (e != NULL) {
			/* Re-set error to diag area. */
			diag_set_error(&fiber()->diag, e);
			return lua_error(L);
		}
	}
	e = luaT_error_create(L, 2);
	if (e == NULL)
		return luaL_error(L, "box.error(): bad arguments");
	diag_set_error(&fiber()->diag, e);
	return luaT_error(L);
}

static int
luaT_error_last(lua_State *L)
{
	if (lua_gettop(L) >= 1)
		luaL_error(L, "box.error.last(): bad arguments");

	struct error *e = box_error_last();
	if (e == NULL) {
		lua_pushnil(L);
		return 1;
	}

	luaT_pusherror(L, e);
	return 1;
}

static int
luaT_error_new(lua_State *L)
{
	if (lua_gettop(L) == 0) {
		return luaL_error(L, "Usage: box.error.new(code, args) or "\
				     "box.error.new(type, args)");
	}
	struct error *e = luaT_error_create(L, 1);
	if (e == NULL) {
		return luaL_error(L, "Usage: box.error.new(code, args) or "\
				     "box.error.new(type, args)");
	}
	lua_settop(L, 0);
	luaT_pusherror(L, e);
	return 1;
}

static int
luaT_error_custom_type(lua_State *L)
{
	struct error *e = luaL_checkerror(L, -1);

	const char *custom_type = box_custom_error_type(e);
	if (custom_type == NULL) {
		lua_pushfstring(L, "The error has't custom type");
		return 1;
	}

	lua_pushstring(L, custom_type);
	return 1;
}

static int
luaT_error_set_lua_traceback(lua_State *L)
{
	if (lua_gettop(L) < 2)
		return luaL_error(L, "Usage: box.error.set_lua_traceback"\
				     "(error, traceback)");

	struct error *e = luaL_checkerror(L, 1);

	if (lua_type(L, 2) == LUA_TSTRING) {
		error_set_lua_traceback(e, lua_tostring(L, 2));
	} else {
		return luaL_error(L, "Usage: box.error.set_lua_traceback"\
				     "(error, traceback)");
	}

	return 0;
}

static int
luaT_error_clear(lua_State *L)
{
	if (lua_gettop(L) >= 1)
		luaL_error(L, "box.error.clear(): bad arguments");

	box_error_clear();
	return 0;
}

static int
luaT_error_set(struct lua_State *L)
{
	if (lua_gettop(L) == 0)
		return luaL_error(L, "Usage: box.error.set(error)");
	struct error *e = luaL_checkerror(L, 1);
	diag_set_error(&fiber()->diag, e);
	return 0;
}

static int
luaT_error_cfg(struct lua_State *L)
{
	if (lua_gettop(L) < 1 || !lua_istable(L, 1))
		return luaL_error(L, "Usage: box.error.cfg({}})");

	lua_getfield(L, 1, "traceback_supplementation");
	if (lua_isnil(L, -1) == 0)
		error_set_traceback_supplementation(lua_toboolean(L, -1));
	lua_pop(L, 1);

	return 0;
}

static int
lbox_errinj_set(struct lua_State *L)
{
	char *name = (char*)luaL_checkstring(L, 1);
	struct errinj *errinj;
	errinj = errinj_by_name(name);
	if (errinj == NULL) {
		say_error("%s", name);
		lua_pushfstring(L, "error: can't find error injection '%s'", name);
		return 1;
	}
	switch (errinj->type) {
	case ERRINJ_BOOL:
		errinj->bparam = lua_toboolean(L, 2);
		break;
	case ERRINJ_INT:
		errinj->iparam = luaL_checkint64(L, 2);
		break;
	case ERRINJ_DOUBLE:
		errinj->dparam = lua_tonumber(L, 2);
		break;
	default:
		lua_pushfstring(L, "error: unknown injection type '%s'", name);
		return 1;
	}

	lua_pushstring(L, "ok");
	return 1;
}

static int
lbox_errinj_push_value(struct lua_State *L, const struct errinj *e)
{
	switch (e->type) {
	case ERRINJ_BOOL:
		lua_pushboolean(L, e->bparam);
		return 1;
	case ERRINJ_INT:
		luaL_pushint64(L, e->iparam);
		return 1;
	case ERRINJ_DOUBLE:
		lua_pushnumber(L, e->dparam);
		return 1;
	default:
		unreachable();
		return 0;
	}
}

static int
lbox_errinj_get(struct lua_State *L)
{
	char *name = (char*)luaL_checkstring(L, 1);
	struct errinj *e = errinj_by_name(name);
	if (e != NULL)
		return lbox_errinj_push_value(L, e);
	lua_pushfstring(L, "error: can't find error injection '%s'", name);
	return 1;
}

static inline int
lbox_errinj_cb(struct errinj *e, void *cb_ctx)
{
	struct lua_State *L = (struct lua_State*)cb_ctx;
	lua_pushstring(L, e->name);
	lua_newtable(L);
	lua_pushstring(L, "state");
	lbox_errinj_push_value(L, e);
	lua_settable(L, -3);
	lua_settable(L, -3);
	return 0;
}

static int
lbox_errinj_info(struct lua_State *L)
{
	lua_newtable(L);
	errinj_foreach(lbox_errinj_cb, L);
	return 1;
}

void
box_lua_error_init(struct lua_State *L) {
	static const struct luaL_Reg errorlib[] = {
		{NULL, NULL}
	};
	luaL_register_module(L, "box.error", errorlib);
	for (int i = 0; i < box_error_code_MAX; i++) {
		const char *name = box_error_codes[i].errstr;
		if (strstr(name, "UNUSED") || strstr(name, "RESERVED"))
			continue;
		assert(strncmp(name, "ER_", 3) == 0);
		lua_pushnumber(L, i);
		/* cut ER_ prefix from constant */
		lua_setfield(L, -2, name + 3);
	}
	lua_newtable(L);
	{
		lua_pushcfunction(L, luaT_error_call);
		lua_setfield(L, -2, "__call");

		lua_newtable(L);
		{
			lua_pushcfunction(L, luaT_error_last);
			lua_setfield(L, -2, "last");
		}
		{
			lua_pushcfunction(L, luaT_error_clear);
			lua_setfield(L, -2, "clear");
		}
		{
			lua_pushcfunction(L, luaT_error_new);
			lua_setfield(L, -2, "new");
		}
		{
			lua_pushcfunction(L, luaT_error_set);
			lua_setfield(L, -2, "set");
		}
		{
			lua_pushcfunction(L, luaT_error_cfg);
			lua_setfield(L, -2, "cfg");
		}
		{
			lua_pushcfunction(L, luaT_error_custom_type);
			lua_setfield(L, -2, "custom_type");
		}
		{
			lua_pushcfunction(L, luaT_error_set_lua_traceback);
			lua_setfield(L, -2, "set_lua_traceback");
		}
		lua_setfield(L, -2, "__index");
	}
	lua_setmetatable(L, -2);

	lua_pop(L, 1);

	static const struct luaL_Reg errinjlib[] = {
		{"info", lbox_errinj_info},
		{"set", lbox_errinj_set},
		{"get", lbox_errinj_get},
		{NULL, NULL}
	};
	/* box.error.injection is not set by register_module */
	luaL_register_module(L, "box.error.injection", errinjlib);
	lua_pop(L, 1);
}
