#!/usr/bin/env tarantool

local yaml = require('yaml').new()
yaml.cfg{
    encode_invalid_numbers = true,
    encode_load_metatables = true,
    encode_use_tostring    = true,
    encode_invalid_as_nil  = true,
}
local test = require('tap').test('table')
test:plan(35)

do -- check basic table.copy (deepcopy)
    local example_table = {
        {1, 2, 3},
        {"help, I'm very nested", {{{ }}} }
    }

    local copy_table = table.deepcopy(example_table)

    test:is_deeply(
        example_table,
        copy_table,
        "checking, that deepcopy behaves ok"
    )
    test:isnt(
        example_table,
        copy_table,
        "checking, that tables are different"
    )
    test:isnt(
        example_table[1],
        copy_table[1],
        "checking, that tables are different"
    )
    test:isnt(
        example_table[2],
        copy_table[2],
        "checking, that tables are different"
    )
    test:isnt(
        example_table[2][2],
        copy_table[2][2],
        "checking, that tables are different"
    )
    test:isnt(
        example_table[2][2][1],
        copy_table[2][2][1],
        "checking, that tables are different"
    )
end

do -- check basic table.copy (deepcopy)
    local example_table = {
        {1, 2, 3},
        {"help, I'm very nested", {{{ }}} }
    }

    local copy_table = table.copy(example_table, true)

    test:is_deeply(
        example_table,
        copy_table,
        "checking, that deepcopy behaves ok + shallow"
    )
    test:isnt(
        example_table,
        copy_table,
        "checking, that tables are different + shallow"
    )
    test:is(
        example_table[1],
        copy_table[1],
        "checking, that tables are the same + shallow"
    )
    test:is(
        example_table[2],
        copy_table[2],
        "checking, that tables are the same + shallow"
    )
    test:is(
        example_table[2][2],
        copy_table[2][2],
        "checking, that tables are the same + shallow"
    )
    test:is(
        example_table[2][2][1],
        copy_table[2][2][1],
        "checking, that tables are the same + shallow"
    )
end

do -- check cycle resolution for table.copy (deepcopy)
    local recursive_table_1 = {}
    local recursive_table_2 = {}

    recursive_table_1[1] = recursive_table_2
    recursive_table_2[1] = recursive_table_1

    local copy_table_1 = table.deepcopy(recursive_table_1)
    local copy_table_2 = table.deepcopy(recursive_table_2)

    test:isnt(
        copy_table_1,
        recursive_table_1,
        "table 1. checking, that tables are different"
    )
    test:isnt(
        copy_table_1[1],
        recursive_table_1[1],
        "table 1. checking, that tables are different"
    )
    test:isnt(
        copy_table_1[1][1],
        recursive_table_1[1][1],
        "table 1. checking, that tables are different"
    )
    test:is(
        copy_table_1,
        copy_table_1[1][1],
        "table 1. checking, that cyclic reference is ok"
    )

    test:isnt(
        copy_table_2,
        recursive_table_2,
        "table 2. checking, that tables are different"
    )
    test:isnt(
        copy_table_2[1],
        recursive_table_2[1],
        "table 2. checking, that tables are different"
    )
    test:isnt(
        copy_table_2[1][1],
        recursive_table_2[1][1],
        "table 2. checking, that tables are different"
    )
    test:is(
        copy_table_2,
        copy_table_2[1][1],
        "table 2. checking, that cyclic reference is ok"
    )
end

do -- check usage of __copy metamethod
    local copy_mt = nil; copy_mt = {
        __copy = function(self)
            local new_self = { a = 1}
            return setmetatable(new_self, copy_mt)
        end
    }
    local one_self = setmetatable({ a = 2 }, copy_mt)
    local another_self = table.deepcopy(one_self)

    test:isnt(one_self, another_self, "checking that output tables differs")
    test:is(
        getmetatable(one_self),
        getmetatable(another_self),
        "checking that we've called __copy"
    )
    test:isnt(one_self.a, another_self.a, "checking that we've called __copy")
end

do -- check usage of __copy metamethod + shallow
    local copy_mt = nil; copy_mt = {
        __copy = function(self)
            local new_self = { a = 1}
            return setmetatable(new_self, copy_mt)
        end
    }
    local one_self = setmetatable({ a = 2 }, copy_mt)
    local another_self = table.copy(one_self, true)

    test:isnt(
        one_self,
        another_self,
        "checking that output objects differs + shallow"
    )
    test:is(
        getmetatable(one_self),
        getmetatable(another_self),
        "checking that we've called __copy + shallow (same obj types)"
    )
    test:isnt(
        one_self.a,
        another_self.a,
        "checking that we've called __copy + shallow (diff obj values)"
    )
end

do -- check usage of not __copy metamethod on second level + shallow
    local copy_mt = nil; copy_mt = {
        __copy = function(self)
            local new_self = { a = 1 }
            return setmetatable(new_self, copy_mt)
        end
    }
    local one_self = { setmetatable({ a = 2 }, copy_mt) }
    local another_self = table.copy(one_self, true)

    test:isnt(
        one_self, another_self,
        "checking that output tables differs + shallow"
    )
    test:isnil(
        getmetatable(one_self),
        "checking that we've called __copy + shallow and no mt"
    )
    test:isnil(
        getmetatable(another_self),
        "checking that we've called __copy + shallow and no mt"
    )
    test:is(
        one_self[1],
        another_self[1],
        "checking that we've called __copy + shallow and object is the same"
    )
    test:is(
        one_self[1].a,
        another_self[1].a,
        "checking that we've called __copy + shallow and object val is the same"
    )
end

do -- gh-4340: deepcopy doesn't handle __metatable correctly.
    local original = {
        content = 'string'
    }
    setmetatable(original, { __metatable = 'protection' })
    local copy = table.deepcopy(original)
    test:is(
            copy.content,
            original.content,
            "checking that original string was copied"
    )
    test:is(
            getmetatable(copy),
            'protection',
            "checking that __metatable was correctly copied"
    )
end

do -- gh-4770: deepcopy uses __pairs for iteration over table.
    local original = { a = 1, b = 2 }

    local function custom_pairs(self)
        local function step(tbl, k)
            local k, v = next(tbl, k)
            if v ~= nil then
                v = v + 1
            end
            return k, v
        end
        return step, self, nil
    end

    setmetatable(original, {__pairs = custom_pairs })

    -- Don't use is deeply as it could use pairs for check
    local copy = table.deepcopy(original)
    test:is(original.a, copy.a,
            "checking that the first values is correctly copied")
    test:is(original.b, copy.b,
            "checking that the second values is correctly copied")
end

os.exit(test:check() == true and 0 or 1)
