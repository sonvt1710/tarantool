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
#define EXPORT(func) extern void ** func(void)

/**
 * The file is a hack to force the linker keep the needed symbols
 * in the result tarantool executable file.
 *
 * Problem is that if a symbol is defined but never used, the
 * linker may throw it away. But many symbols are needed for Lua
 * FFI and for the public C API used by dynamic modules.
 *
 * This file creates a 'false usage' of needed symbols. It takes
 * pointers at them and does something with them, so as the
 * compiler and linker couldn't remove it.
 *
 * Some exporters may represent modules having submodules, and may
 * aggregate symbols from them.
 *
 * Add new exporters here. Keep them in alphabetical order.
 */

EXPORT(base64_export_syms);
EXPORT(clock_export_syms);
EXPORT(scramble_export_syms);
EXPORT(tarantool_lua_export_syms);

void
export_syms(void)
{
	void *syms[] = {
		base64_export_syms,
		clock_export_syms,
		scramble_export_syms,
		tarantool_lua_export_syms,
	};
	const int func_count = sizeof(syms) / sizeof(syms[0]);
	for (int i = 0; i < func_count; ++i)
		((void **(*)(void))syms[i])();
}

#undef EXPORT
