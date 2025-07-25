--[[
The test for Tarantool allows you to randomly generate DDL and DML
operations for spaces uses vinyl and memtx engines and toggle
random error injections. All random operations and settings depend
on the seed, which is generated at the very beginning of the test.

by default the script uses a directory `test_engine_dir` in
a current directory. Custom test directory can be specified with
option `--test_dir`. The script will clean up the directory before
testing if it exists.

Usage: tarantool test_engine.lua
]]

local arrow
local console = require('console')
local fiber = require('fiber')
local fio = require('fio')
local ffi = require('ffi')
local fun = require('fun')
local json = require('json')
local log = require('log')
local math = require('math')

-- Tarantool datatypes.
local datetime = require('datetime')
local decimal = require('decimal')
local msgpack = require('msgpack')
local uuid = require('uuid')

local test_dir_name = 'test_engine_dir'
local DEFAULT_TEST_DIR = fio.pathjoin(fio.cwd(), test_dir_name)

local params = require('internal.argparse').parse(arg, {
    { 'engine', 'string' },
    { 'fault_injection', 'boolean' },
    { 'h', 'boolean' },
    { 'seed', 'number' },
    { 'test_duration', 'number' },
    { 'test_dir', 'string' },
    { 'verbose', 'boolean' },
    { 'workers', 'number' },
})

local function counter()
    local i = 0
    return function()
        i = i + 1
        return i
    end
end

local index_id_func = counter()

if params.help or params.h then
    print(([[

 Usage: tarantool test_engine.lua [options]

 Options can be used with '--', followed by the value if it's not
 a boolean option. The options list with default values:

   workers <number, 50>                  - number of fibers to run in parallel
   test_duration <number, 2*60>          - test duration time (sec)
   test_dir <string, ./%s>  - path to a test directory
   engine <string, 'vinyl'>              - engine ('vinyl', 'memtx', 'memcs')
   fault_injection <boolean, false>      - enable fault injection
   seed <number>                         - set a PRNG seed
   verbose <boolean, false>              - enable verbose logging
   help (same as -h)                     - print this message
]]):format(test_dir_name))
    os.exit(0)
end

-- Number of workers.
local arg_num_workers = params.workers or 50

-- Test duration time.
local arg_test_duration = params.test_duration or 2*60

-- Test directory.
local arg_test_dir = params.test_dir or DEFAULT_TEST_DIR

-- Tarantool engine.
local arg_engine = params.engine or 'vinyl'

local arg_verbose = params.verbose or false

local arg_fault_injection = params.fault_injection or false

local seed = params.seed or os.time()
math.randomseed(seed)
log.info('Random seed: %d', seed)

-- MEMCS engine requires Tarantool Enterprise and a Lua C module:
-- `arrow_c_api_wrapper`.
if arg_engine == 'memcs' then
    local tarantool = require('tarantool')
    if tarantool.package ~= 'Tarantool Enterprise' then
        error('Engine ' .. arg_engine .. ' requires Tarantool Enterprise')
    end
    arrow = require('arrow_c_api_wrapper')
end

-- The table contains a whitelist of errors that will be ignored
-- by test. Each item is a Lua pattern, special characters
-- should be escaped: ^ $ ( ) % . [ ] * + - ?
-- These characters can also be used in the pattern as normal
-- characters by prefixing them with a "%" character, so "%%"
-- becomes "%", "%[" becomes "[", etc.
local err_pat_whitelist = {
    -- Multi-engine transactions aren't supported, see
    -- https://github.com/tarantool/tarantool/issues/1958 and
    -- https://github.com/tarantool/tarantool/issues/1803.
    "Can not perform index build in a multi-statement transaction",
    -- DDL on a space is locked until the end of the current DDL
    -- operation.
    "the space is already being modified",
    -- The test actively uses error injections that can cause such errors.
    "Error injection '[%w_ ]+'",
    -- The test actively uses transactions that concurrently
    -- changes a data in a space, this can lead to errors below.
    "Transaction has been aborted by conflict",
    "Transaction has been aborted by fiber yield",
    "Vinyl does not support rebuilding the primary index of a non%-empty space",
    "fiber is cancelled",
    "fiber slice is exceeded",
    "Can not perform index build in a multi%-statement transaction",
    "Index '[%w_]+' %(HASH%) of space '[%w_]+' %(memtx%) does not support pagination",
    "Can't create or modify index '[%w_]+' in space '[%w_]+': primary key must be unique",
    "Can't create or modify index '[%w_]+' in space '[%w_]+': hint is only reasonable with memtx tree index",
    "Get%(%) doesn't support partial keys and non%-unique indexes",
    "Failed to allocate %d+ bytes in [%w_ ]+ for [%w_]+",
    "Tuple field %d+ %([%w_]+%) type does not match one required by " ..
        "operation: expected %w+, got nil",
    "MVCC is unavailable for storage engine '[%w_]+' so it cannot be used " ..
        "in the same transaction with '[%w_]+', which supports MVCC",
    "Vinyl does not support executing a statement in a transaction that is " ..
        "not allowed to yield",
    "Can't modify space '[%d]+': the space was concurrently modified",
    "Failed to write to disk",
    "WAL has a rollback in progress",
    -- MEMCS-specific errors.
    "Index '[%w_]+' %(TREE%) of space '[%w_]+' %(memcs%) does not support pagination",
    "Arrow stream does not support field type '[%w_]+'",
    "box_insert_arrow: field [%d]+ has unsupported type",
    "Engine 'memcs' does not support variable field count",
    "Engine 'memcs' does not support primary index rebuild",
    "Engine 'memcs' does not support clearing space field nullability",
}

local function keys(t)
    assert(next(t) ~= nil)
    local table_keys = {}
    for k, _ in pairs(t) do
        table.insert(table_keys, k)
    end
    return table_keys
end

local function contains(t, value)
    for _, v in pairs(t) do
        if value == v then
            return true
        end
    end
    return false
end

local function rmtree(path)
    log.info('CLEANUP %s', path)
    if (fio.path.is_file(path) or fio.path.is_link(path)) then
        fio.unlink(path)
        return
    end
    if fio.path.is_dir(path) then
        for _, p in pairs(fio.listdir(path)) do
            rmtree(fio.pathjoin(path, p))
        end
    end
end

local function rand_char()
    return string.char(math.random(97, 97 + 25))
end

local function rand_string(length)
    length = length or math.random(8, 256)
    local res = ''
    for _ = 1, length do
        res = res .. rand_char()
    end
    return res
end

local function oneof(tbl)
    assert(type(tbl) == 'table')
    assert(next(tbl) ~= nil)

    local n = table.getn(tbl)
    local idx = math.random(1, n)
    return tbl[idx]
end

local function unique_ids(max_num_ids)
    local ids = {}
    for i = 1, max_num_ids do
        table.insert(ids, i)
    end
    return function()
        local id = math.random(#ids)
        local v = ids[id]
        assert(v)
        table.remove(ids, id)
        return v
    end
end

-- Forward declaration.
local index_create_op

local function random_int()
    return math.floor(math.random() * 10^12)
end

-- Maximal possible R-tree dimension,
-- see <src/lib/salad/rtree.h>.
local RTREE_MAX_DIMENSION = 20

local RTREE_DIMENSION = math.random(RTREE_MAX_DIMENSION)

-- RTREE is a single index that support arrays, length of arrays
-- depends on a RTREE's dimension.
local function random_array()
    local n = RTREE_DIMENSION * 2
    local arr = {}
    for i = 1, n do
        table.insert(arr, i)
    end
    return arr
end

local function random_map()
    local n = math.random(1, 10)
    local t = {}
    for i = 1, n do
        t[tostring(i)] = i
    end
    return t
end

-- List of Tarantool types. Each type is a key-value pair where key is a name
-- of an type and value is a table with following keys:
-- generator - function generating a random value of the type.
-- operations - list of tuple:update(...) operations supported by the type.
-- [optional] engines - list of supported engines. If set, all spaces
--                      with unsupported engine will not use the type.
--
-- '+' - Numeric.
-- '-' - Numeric.
-- '&' - Numeric.
-- '|' - Numeric.
-- '^' - Numeric.
-- '#' - For deletion.
-- '=' - For assignment.
-- ':' - For string splice.
-- '!' - For insertion of a new field.
-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/#indexes-tree
-- TODO: support varbinary.
-- NOTE: scalar type may include nil, boolean, integer, unsigned,
-- number, decimal, string, varbinary, or uuid values. All these
-- datatypes tested separately, except varbinary, so scalar is
-- unused.
-- NOTE: map is cannot be indexed, so it is unused.
local tarantool_type = {
    ['array'] = {
        generator = random_array,
        operations = {'=', '!'},
    },
    ['boolean'] = {
        generator = function()
            return oneof({true, false})
        end,
        operations = {'=', '!'},
    },
    ['decimal'] = {
        generator = function()
            return decimal.new(random_int())
        end,
        operations = {'+', '-'},
    },
    ['datetime'] = {
        generator = function()
            return datetime.new({timestamp = os.time()})
        end,
        operations = {'=', '!'},
    },
    ['double'] = {
        generator = function()
            return math.random() * 10^12
        end,
        operations = {'+', '-'},
    },
    ['integer'] = {
        generator = random_int,
        operations = {'+', '-'},
        engines = {'memtx', 'vinyl'},
    },
    ['map'] = {
        generator = random_map,
        operations = {'=', '!'},
    },
    ['number'] = {
        generator = random_int,
        operations = {'+', '-'},
    },
    ['string'] = {
        generator = rand_string,
        operations = {'=', '!'}, -- XXX: ':'
    },
    ['unsigned'] = {
        generator = function()
            return math.abs(random_int())
        end,
        operations = {'#', '+', '-', '&', '|', '^'},
    },
    ['uuid'] = {
        generator = uuid.new,
        operations = {'=', '!'},
    },
    ['int8'] = {
        generator = function()
            return math.random(-2^7, 2^7 - 1)
        end,
        operations = {'+', '-'},
    },
    ['uint8'] = {
        generator = function()
            return math.random(0, 2^8 - 1)
        end,
        operations = {'+', '-', '&', '|', '^'},
    },
    ['int16'] = {
        generator = function()
            return math.random(-2^15, 2^15 - 1)
        end,
        operations = {'+', '-'},
    },
    ['uint16'] = {
        generator = function()
            return math.random(0, 2^16 - 1)
        end,
        operations = {'+', '-', '&', '|', '^'},
    },
    ['int32'] = {
        generator = function()
            return math.random(-2^31, 2^31 - 1)
        end,
        operations = {'+', '-'},
    },
    ['uint32'] = {
        generator = function()
            return math.random(0, 2^32 - 1)
        end,
        operations = {'+', '-', '&', '|', '^'},
    },
    ['int64'] = {
        generator = function()
            local v = math.random(-2^63, 2^63 - 1)
            return ffi.cast('int64_t', v)
        end,
        operations = {'+', '-'},
    },
    ['uint64'] = {
        generator = function()
            local v = math.random(0, 2^64 - 1)
            return ffi.cast('uint64_t', v)
        end,
        operations = {'+', '-', '&', '|', '^'},
    },
    ['float32'] = {
        generator = function()
            local v = math.random() * 10^12
            return ffi.cast('float', v)
        end,
        operations = {'+', '-'},
    },
    ['float64'] = {
        generator = function()
            local v = math.random() * 10^12
            return ffi.cast('double', v)
        end,
        operations = {'+', '-'},
    },
}

-- Returns Tarantool types (see the `tarantool_type` table above)
-- supported by the given engine.
local function supported_tarantool_types(engine)
    local function filter(_name, data)
        return data.engines == nil or contains(data.engines, engine)
    end
    return fun.iter(tarantool_type):filter(filter):tomap()
end

-- The name value may be any string, provided that two fields
-- do not have the same name.
-- The type value may be any of allowed types:
-- any | unsigned | string | integer | number | varbinary |
-- boolean | double | decimal | uuid | array | map | scalar,
-- but for creating an index use only indexed fields;
-- (Optional) The is_nullable boolean value specifies whether
-- nil can be used as a field value. See also: key_part.is_nullable.
-- (Optional) The collation string value specifies the collation
-- used to compare field values. See also: key_part.collation.
-- (Optional) The constraint table specifies the constraints that
-- the field value must satisfy.
-- (Optional) The foreign_key table specifies the foreign keys
-- for the field.
--
-- See https://www.tarantool.io/ru/doc/latest/reference/reference_lua/box_space/format/.
local function random_space_format(engine)
    assert(type(engine) == 'string')
    local types = supported_tarantool_types(engine)
    local space_format = {}
    local min_num_fields = table.getn(keys(types))
    local max_num_fields = min_num_fields + 10
    local num_fields = math.random(min_num_fields, max_num_fields)
    for i, datatype in ipairs(keys(types)) do
        table.insert(space_format, {
            name =('field_%d'):format(i),
            type = datatype,
            is_nullable = oneof({true, false}),
        })
    end
    for i = min_num_fields - 1, num_fields - min_num_fields - 1 do
        table.insert(space_format, {
            name =('field_%d'):format(i),
            type = oneof(keys(types)),
            is_nullable = oneof({true, false}),
        })
    end

    return space_format
end

-- Iterator types for indexes.
-- See https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_index/pairs/#box-index-iterator-types
-- For information about nullable fields, see:
-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_space/create_index/#lua-data.key_part.is_nullable
-- TODO: support `multikey`.
-- TODO: support `pagination`.
local tarantool_indices = {
    HASH = {
        iterator_type = {
            'ALL',
            'EQ',
        },
        data_type = {
            ['boolean'] = true,
            ['decimal'] = true,
            ['double'] = true,
            ['integer'] = true,
            ['number'] = true,
            ['scalar'] = true,
            ['string'] = true,
            ['unsigned'] = true,
            ['uuid'] = true,
            ['varbinary'] = true,
        },
        is_multipart = true,
        is_min_support = false,
        is_max_support = false,
        is_nullable_support = false,
        is_unique_support = true,
        is_non_unique_support = false,
        is_primary_key_support = true,
        is_partial_search_support = false,
    },
    BITSET = {
        iterator_type = {
            'ALL',
            'BITS_ALL_NOT_SET',
            'BITS_ALL_SET',
            'BITS_ANY_SET',
            'EQ',
        },
        data_type = {
            ['string'] = true,
            ['unsigned'] = true,
            ['varbinary'] = true,
        },
        is_multipart = false,
        is_min_support = false,
        is_max_support = false,
        is_nullable_support = false,
        is_unique_support = false,
        is_non_unique_support = true,
        is_primary_key_support = false,
        is_partial_search_support = false,
    },
    TREE = {
        iterator_type = {
            'ALL',
            'EQ',
            'GE',
            'GT',
            'LE',
            'LT',
            'REQ',
        },
        data_type = {
            ['boolean'] = true,
            ['datetime'] = true,
            ['decimal'] = true,
            ['double'] = true,
            ['integer'] = true,
            ['number'] = true,
            ['scalar'] = true,
            ['string'] = true,
            ['unsigned'] = true,
            ['uuid'] = true,
            ['varbinary'] = true,
        },
        is_multipart = true,
        is_min_support = true,
        is_max_support = true,
        is_nullable_support = true,
        is_unique_support = true,
        is_non_unique_support = true,
        is_primary_key_support = true,
        is_partial_search_support = true,
    },
    RTREE = {
        iterator_type = {
            'ALL',
            'EQ',
            'GE',
            'GT',
            'LE',
            'LT',
            'NEIGHBOR',
            'OVERLAPS',
        },
        data_type = {
            ['array'] = true,
        },
        is_multipart = false,
        is_min_support = false,
        is_max_support = false,
        is_nullable_support = false,
        is_unique_support = false,
        is_non_unique_support = true,
        is_primary_key_support = false,
        is_partial_search_support = true,
    },
}

-- Note that the linearizable isolation level can't be set as
-- default and can be used for a specific transaction only.
-- See https://www.tarantool.io/en/doc/latest/platform/atomic/txn_mode_mvcc/.
-- Note that 'linearizable' makes sense when space is synchronous,
-- the test uses only local spaces, so 'linearizable' is not used.
local isolation_levels = {
    'best-effort',
    'read-committed',
    'read-confirmed',
}

local function select_op(space, idx_type, key)
    local select_opts = {
        iterator = oneof(tarantool_indices[idx_type].iterator_type),
        -- The maximum number of tuples.
        limit = math.random(100, 500),
        -- The number of tuples to skip.
        offset = math.random(100),
        -- A tuple or the position of a tuple (tuple_pos) after
        -- which select starts the search.
        after = box.NULL,
        -- If true, the select method returns the position of
        -- the last selected tuple as the second value.
        fetch_pos = oneof({true, false}),
    }
    space:select(key, select_opts)
end

local function get_op(space, key)
    space:get(key)
end

local function put_op(space, tuple)
    space:put(tuple)
end

local function delete_op(space, tuple)
    space:delete(tuple)
end

local function insert_op(space, tuple)
    space:insert(tuple)
end

local function upsert_op(space, tuple, tuple_ops)
    assert(next(tuple_ops) ~= nil)
    space:upsert(tuple, tuple_ops)
end

local function update_op(space, key, tuple_ops)
    assert(next(tuple_ops) ~= nil)
    space:update(key, tuple_ops)
end

local function replace_op(space, tuple)
    space:replace(tuple)
end

local function bsize_op(space)
    space:bsize()
end

local function len_op(space)
    space:len()
end

local function format_op(space, space_format)
    space:format(space_format)
end

local function insert_arrow_op(space, batch)
    arrow.box_insert_arrow(space.id, batch)
end

local function setup(engine_name, space_id_func, test_dir, verbose)
    log.info('SETUP')
    assert(engine_name == 'memtx' or
           engine_name == 'vinyl' or
           engine_name == 'memcs')
    -- Configuration reference (box.cfg),
    -- https://www.tarantool.io/en/doc/latest/reference/configuration/

    local vinyl_range_size = oneof({1, 4, 16, 128}) * 1024
    local vinyl_page_size = oneof({1, 4, 16, 128, 512}) * 1024
    -- vinyl_page_size must be in range (0, vinyl_range_size].
    vinyl_page_size = math.min(vinyl_page_size, vinyl_range_size)

    local box_cfg_options = {
        checkpoint_count = math.random(5),
        checkpoint_interval = math.random(60),
        checkpoint_wal_threshold = math.random(1024),
        iproto_threads = math.random(1, 10),
        memtx_allocator = oneof({'system', 'small'}),
        memtx_memory = 1024 * 1024,
        memtx_sort_threads = math.random(1, 256),
        memtx_use_mvcc_engine = oneof({true, false}),
        readahead = 16320,
        slab_alloc_factor = math.random(1, 2),
        vinyl_bloom_fpr = math.random(50) / 100,
        vinyl_cache = oneof({0, 2}) * 1024 * 1024,
        vinyl_defer_deletes = oneof({true, false}),
        vinyl_memory = oneof({8, 16, 32, 64, 128}) * 1024 * 1024,
        vinyl_page_size = vinyl_page_size,
        vinyl_range_size = vinyl_range_size,
        vinyl_read_threads = math.random(2, 10),
        vinyl_run_count_per_level = oneof({1, 2, 4, 8, 16, 32}),
        vinyl_run_size_ratio = math.random(2, 5),
        vinyl_timeout = math.random(1, 5),
        vinyl_write_threads = math.random(2, 10),
        wal_cleanup_delay = 14400,
        wal_dir_rescan_delay = math.random(1, 20),
        wal_max_size = math.random(1024 * 1024 * 1024),
        wal_mode = oneof({'write', 'fsync'}),
        wal_queue_max_size = 16777216,
        work_dir = test_dir,
        worker_pool_threads = math.random(1, 10),
    }
    if box_cfg_options.memtx_use_mvcc_engine then
        box_cfg_options.txn_isolation = oneof(isolation_levels)
    end
    if verbose then
        box_cfg_options.log_level = 'verbose'
    end
    box.cfg(box_cfg_options)
    log.info('FINISH BOX.CFG')

    log.info('CREATE A SPACE')
    local space_format = random_space_format(engine_name)
    -- TODO: support `constraint`.
    -- TODO: support `foreign_key`.
    local space_opts = {
        engine = engine_name,
        field_count = oneof({0, table.getn(space_format)}),
        format = space_format,
        if_not_exists = oneof({true, false}),
        is_local = oneof({true, false}),
    }
    -- Memcs does not support variable field count.
    if space_opts.engine == 'memcs' then
        space_opts.field_count = table.getn(space_format)
    end
    if space_opts.engine == 'memtx' then
        space_opts.temporary = oneof({true, false})
    end
    local space_name = ('test_%d'):format(space_id_func())
    local space = box.schema.space.create(space_name, space_opts)
    index_create_op(space)
    index_create_op(space)
    log.info('FINISH SETUP')
    return space
end

local function cleanup_dir(dir)
    log.info('CLEANUP')
    if dir ~= nil then
        rmtree(dir)
        dir = nil -- luacheck: ignore
    end
end

local function teardown(space)
    log.info('TEARDOWN')
    space:drop()
end

-- Indexes,
-- https://www.tarantool.io/en/doc/latest/concepts/data_model/indexes/
-- space_object:create_index(),
-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/box_space/create_index/
local function index_opts(space, is_primary)
    assert(space ~= nil)
    local opts = {
        if_not_exists = false,
        -- TODO: support `sequence`,
        -- TODO: support functional indices.
    }

    local indices = fun.iter(keys(tarantool_indices)):filter(
        function(x)
            if tarantool_indices[x].is_primary_key_support == is_primary then
                return x
            end
        end):totable()

    if space.engine == 'vinyl' or space.engine == 'memcs' then
        indices = {'TREE'}
    end

    opts.type = oneof(indices)
    -- Primary key must be unique.
    opts.unique = is_primary and
                  true or
                  tarantool_indices[opts.type].is_unique_support

    -- 'hint' is only reasonable with memtx tree index.
    if space.engine == 'memtx' and
       opts.type == 'TREE' then
        opts.hint = true
    end

    if opts.type == 'RTREE' then
        opts.distance = oneof({'euclid', 'manhattan'})
        opts.dimension = RTREE_DIMENSION
    end

    opts.parts = {}
    local space_format = space:format()
    local idx = opts.type
    local possible_fields = fun.iter(space_format):filter(
        function(x)
            -- Primary index must be not nullable.
            if is_primary and x.is_nullable then
                return nil
            end
            if tarantool_indices[idx].data_type[x.type] == true then
                return x
            end
        end):totable()
    local n_parts = math.random(1, table.getn(possible_fields))
    local id = unique_ids(n_parts)
    local is_nullable_support = not is_primary and
        tarantool_indices[opts.type].is_nullable_support
    for i = 1, n_parts do
        local field_id = id()
        local field = possible_fields[field_id]
        -- Randomly set is_nullable if it is supported.
        -- Engine memcs does not support non_nullable index parts over
        -- nullable fields - always set is_nullable in this case.
        local is_nullable = false
        if space.engine == 'memcs' and field.is_nullable then
            is_nullable = true
        elseif field.is_nullable and is_nullable_support then
            is_nullable = oneof({true, false})
        end

        local exclude_null = oneof({false, is_nullable})
        table.insert(opts.parts, {
            field.name, is_nullable = is_nullable,
            exclude_null = exclude_null,
        })
        if not tarantool_indices[opts.type].is_multipart and
           i == 1 then
            break
        end
    end

    return opts
end

function index_create_op(space)
    local idx_id = index_id_func()
    local idx_name = 'idx_' .. idx_id
    local is_primary = idx_id == 1
    local opts = index_opts(space, is_primary)
    space:create_index(idx_name, opts)
end

local function index_drop_op(space)
    if not space.enabled then return end
    local idx = oneof(space.index)
    if idx ~= nil then idx:drop() end
end

local function index_alter_op(_, idx, opts)
    assert(idx)
    assert(opts)
    opts.if_not_exists = nil
    idx:alter(opts)
end

local function index_compact_op(_, idx)
    assert(idx)
    idx:compact()
end

local function index_max_op(_, idx)
    assert(idx)
    if not tarantool_indices[idx.type].is_max_support then
        return
    end
    idx:max()
end

local function index_min_op(_, idx)
    assert(idx)
    if not tarantool_indices[idx.type].is_min_support then
        return
    end
    idx:min()
end

local function index_random_op(_, idx)
    assert(idx)
    if idx.type ~= 'BITSET' and
       idx.type ~= 'RTREE' then
        idx:random()
    end
end

local function index_rename_op(_, idx, idx_name)
    assert(idx)
    idx:rename(idx_name)
end

local function index_stat_op(_, idx)
    assert(idx)
    idx:stat()
end

local function index_get_op(_space, idx, key)
    assert(idx)
    assert(key)
    local index_opts = tarantool_indices[idx.type]
    if not index_opts.is_partial_search_support or
       not index_opts.is_non_unique_support then
        return
    end
    idx:get(key)
end

local function index_select_op(_space, idx, key)
    assert(idx)
    assert(key)
    idx:select(key)
end

local function index_count_op(_, idx)
    assert(idx)
    idx:count()
end

local function index_update_op(_space, key, idx, tuple_ops)
    assert(idx)
    assert(key)
    assert(tuple_ops)
    assert(next(tuple_ops) ~= nil)
    local index_opts = tarantool_indices[idx.type]
    if not index_opts.is_partial_search_support or
       not index_opts.is_non_unique_support then
        return
    end
    idx:update(key, tuple_ops)
end

local function index_delete_op(_space, idx, key)
    assert(idx)
    assert(key)
    local index_opts = tarantool_indices[idx.type]
    if not index_opts.is_partial_search_support or
       not index_opts.is_non_unique_support then
        return
    end
    idx:delete(key)
end

local function index_arrow_stream_op(space, idx, fields, key)
    local mpkey = msgpack.encode(key)
    local batch_size
    if oneof({true, false}) then
        -- We want to read small batches often, so limit max batch size
        -- with 50% probability.
        local max_batch_size = oneof({10, 10^6})
        batch_size = math.random(1, max_batch_size)
        log.info('ARROW_STREAM: explicitly set batch size to ' .. batch_size)
    end
    local stream = arrow.box_index_arrow_stream(space.id, idx.id, fields, mpkey,
                                                batch_size)
    while true do
        if math.random(1, 20) == 1 then
            log.info('ARROW_STREAM: finish early')
            break
        end
        log.info('ARROW_STREAM: stream next')
        local result = arrow.arrow_stream_next(stream)
        -- Print only small batches: huge ones would clutter up the logs.
        if result.row_count <= 10 then
            log.info('ARROW_STREAM: has read batch ' .. json.encode(result))
        else
            log.info('ARROW_STREAM: has read big batch of size ' ..
                     result.row_count)
        end
        if oneof({true, false}) then
            log.info('ARROW_STREAM: yield after batch')
            fiber.yield()
        end
        if result.row_count == 0 then
            break
        end
    end
    arrow.arrow_stream_free(stream)
end


-- Generate random field value, `opts` is a map with options.
-- Available options:
-- - disallow_null (boolean) - do not return NULL even if the field is nullable.
local function random_field_value(field, opts)
    local field_type = field.type
    local type_gen = tarantool_type[field_type].generator
    assert(type(type_gen) == 'function', field_type)

    local disallow_null = opts and opts.disallow_null
    if field.is_nullable and not disallow_null then
        return oneof({box.NULL, type_gen()})
    else
        return type_gen()
    end
end

local function random_tuple(space_format)
    local tuple = {}
    for _, field in ipairs(space_format) do
        table.insert(tuple, random_field_value(field))
    end

    return tuple
end

-- Example of tuple operations: {{'=', 3, 'a'}, {'=', 4, 'b'}}.
--  - operator (string) – operation type represented in string.
--  - field_identifier (number) – what field the operation will
--    apply to.
--  - value (lua_value) – what value will be applied.
local function random_tuple_operations(space)
    local space_format = space:format()
    local num_fields = math.random(table.getn(space_format))
    local tuple_ops = {}
    local id = unique_ids(num_fields)
    for _ = 1, math.random(num_fields) do
        local field_id = id()
        local field = space_format[field_id]
        local operator = oneof(tarantool_type[field.type].operations)
        local value = random_field_value(field, {disallow_null = true})
        table.insert(tuple_ops, {operator, field_id, value})
    end

    return tuple_ops
end

local function random_key(space, idx)
    assert(idx, ('indices: %s'):format(json.encode(space.index)))
    local parts = idx.parts
    local key = {}
    for _, field in ipairs(parts) do
        local type_gen = tarantool_type[field.type].generator
        assert(type(type_gen) == 'function')
        table.insert(key, type_gen())
    end
    return key
end

-- Chooses random space fields and return their indexes,
-- they are not ordered and may be repeated.
-- NB: indexes are zero-based.
local function random_space_field_ids(space)
    local format_size = #space:format()
    local fields = {}
    local fields_num_max = format_size * 2
    local fields_num = math.random(fields_num_max)
    for _ = 1, fields_num do
        table.insert(fields, math.random(0, format_size - 1))
    end
    return fields
end

-- Chooses random fields from index parts and return their
-- indexes, they are not ordered and may be repeated.
-- NB: indexes are zero-based.
local function random_index_field_ids(index)
    local parts = index.parts
    local parts_size = #parts
    local fields = {}
    local fields_num_max = parts_size * 2
    local fields_num = math.random(fields_num_max)
    for _ = 1, fields_num do
        local idx = math.random(parts_size)
        local part = parts[idx]
        local zero_based_fieldno = part.fieldno - 1
        table.insert(fields, zero_based_fieldno)
    end
    return fields
end

-- Generates random arguments for space scanner (arrow_stream) - chooses random
-- index, chooses fields covered by the index and generates a key.
local function random_scanner_args(space)
    local idx_n = oneof(keys(space.index))
    local idx = space.index[idx_n]
    local fields
    -- Primary index covers all fields.
    if idx == 0 then
        fields = random_space_field_ids(space)
    else
        fields = random_index_field_ids(idx)
    end
    return idx, fields, oneof({{}, random_key(space, idx)})
end

-- Generates a batch as a Lua table in a format:
-- {{field_name1, {<values>}}, {field_name2, {<values>}}, ...}.
-- Fields are not repeated, nullable ones can be skipped.
local function random_batch(space)
    local format_size = #space:format()
    local batch = {}
    -- Randomly choose between small and big batch
    local max_batch_size = oneof({10, 100})
    local batch_size = math.random(1, max_batch_size)
    local id = unique_ids(format_size)
    for _ = 1, format_size do
        local i = id()
        local field = space:format()[i]
        local values = {}
        -- Skip the field only if it is nullable.
        local skip_field = oneof({false, field.is_nullable})
        if not skip_field then
            for _ = 1, batch_size do
                table.insert(values, random_field_value(field))
            end
            table.insert(batch, {field.name, values})
        end
    end
    return batch
end

local function box_snapshot()
    local in_progress = box.info.gc().checkpoint_is_in_progress
    if not in_progress then
        box.snapshot()
    end
end

-- List of operations for fuzzer. Each operation is a key-value pair
-- where key is a name of an operation and value is a table with
-- following keys:
-- func - function performing the operation.
-- args - function generating arguments for the operation, accepts
--        the space as the only argument.
-- [optional] engines - list of supported engines. If set, all spaces
--                      with unsupported engine will skip the operation.
local ops = {
    -- DML.
    DELETE_OP = {
        func = delete_op,
        args = function(space) return random_key(space, space.index[0]) end,
    },
    INSERT_OP = {
        func = insert_op,
        args = function(space) return random_tuple(space:format()) end,
    },
    SELECT_OP = {
        func = select_op,
        args = function(space)
            local idx = space.index[0]
            return idx.type, random_key(space, idx)
        end,
    },
    GET_OP = {
        func = get_op,
        args = function(space) return random_key(space, space.index[0]) end,
    },
    PUT_OP = {
        func = put_op,
        args = function(space) return random_tuple(space:format()) end,
    },
    REPLACE_OP = {
        func = replace_op,
        args = function(space) return random_tuple(space:format()) end,
    },
    UPDATE_OP = {
        func = update_op,
        args = function(space)
            local pk = space.index[0]
            return random_key(space, pk), random_tuple_operations(space)
        end,
    },
    UPSERT_OP = {
        func = upsert_op,
        args = function(space)
            return random_tuple(space:format()), random_tuple_operations(space)
        end,
        engines = {'memtx', 'vinyl'},
    },
    BSIZE_OP = {
        func = bsize_op,
        args = function(_) return end,
    },
    LEN_OP = {
        func = len_op,
        args = function(_) return end,
    },
    FORMAT_OP = {
        func = format_op,
        args = function(space) return random_space_format(space.engine) end,
    },

    -- DDL.
    INDEX_ALTER_OP = {
        func = index_alter_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local index = space.index[idx_n]
            local is_primary = index.id == 0
            return index, index_opts(space, is_primary)
        end,
    },
    INDEX_COMPACT_OP = {
        func = index_compact_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_CREATE_OP = {
        func = index_create_op,
        args = function(_) return end,
    },
    INDEX_DROP_OP = {
        func = index_drop_op,
        args = function(space)
            local indices = keys(space.index)
            -- Don't touch primary index.
            table.remove(indices, 0)
            local idx_n = oneof(indices)
            return space.index[idx_n]
        end,
    },
    INDEX_GET_OP = {
        func = index_get_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return idx, random_key(space, idx)
        end,
    },
    INDEX_SELECT_OP = {
        func = index_select_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return idx, random_key(space, idx)
        end,
    },
    INDEX_MIN_OP = {
        func = index_min_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_MAX_OP = {
        func = index_max_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_RANDOM_OP = {
        func = index_random_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
        engines = {'memtx'},
    },
    INDEX_COUNT_OP = {
        func = index_count_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },
    INDEX_UPDATE_OP = {
        func = index_update_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return random_key(space, idx), idx, random_tuple_operations(space)
        end,
        engines = {'memtx', 'vinyl'},
    },
    INDEX_DELETE_OP = {
        func = index_delete_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            local idx = space.index[idx_n]
            return idx, random_key(space, idx)
        end,
        engines = {'memtx', 'vinyl'},
    },
    INDEX_RENAME_OP = {
        func = index_rename_op,
        args = function(space)
            local idx_name = rand_string()
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n], idx_name
        end,
    },
    INDEX_STAT_OP = {
        func = index_stat_op,
        args = function(space)
            local idx_n = oneof(keys(space.index))
            return space.index[idx_n]
        end,
    },

    TX_BEGIN = {
        func = function()
            if box.is_in_txn() then
                return
            end
            local txn_opts = {}
            if box.cfg.memtx_use_mvcc_engine then
               txn_opts.txn_isolation = oneof(isolation_levels)
            end
            box.begin(txn_opts)
        end,
        args = function(_) return end,
    },
    TX_COMMIT = {
        func = function()
            if box.is_in_txn() then
                box.commit()
            end
        end,
        args = function(_) return end,
    },
    TX_ROLLBACK = {
        func = function()
            if box.is_in_txn() then
                box.rollback()
            end
        end,
        args = function(_) return end,
    },

    SNAPSHOT_OP = {
        func = box_snapshot,
        args = function(_) return end,
    },

    -- memcs-specific.
    INDEX_ARROW_STREAM_OP = {
        func = index_arrow_stream_op,
        args = random_scanner_args,
        engines = {'memcs'},
    },
    INSERT_ARROW_OP = {
        func = insert_arrow_op,
        args = random_batch,
        engines = {'memcs'},
    },
}

local function apply_op(space, op_name)
    local op = ops[op_name]
    if op.engines ~= nil and not contains(op.engines, space.engine) then
        log.info('SKIP: %s does not support %s', space.engine, op_name)
        return
    end
    local func = op.func
    local args = { op.args(space) }
    log.info('%s %s', op_name, json.encode(args))
    local pcall_args = {func, space, unpack(args)}
    local ok, err = pcall(unpack(pcall_args))
    if ok ~= true then
        log.info('ERROR: opname "%s", err "%s", args %s',
                 op_name, err, json.encode(args))
    end
    return err
end

local shared_gen_state

local function worker_func(id, space, test_gen, deadline)
    log.info('Worker #%d has started.', id)
    local gen, param, state = test_gen:unwrap()
    shared_gen_state = state
    local errors = {}
    while os.clock() <= deadline do
        local operation_name
        state, operation_name = gen(param, shared_gen_state)
        if state == nil then
            break
        end
        shared_gen_state = state
        local err = apply_op(space, operation_name)
        table.insert(errors, err)
    end
    log.info('Worker #%d has finished.', id)
    return errors
end

-- Disabled all enabled error injections.
local function disable_all_errinj(errinj, space)
    local enabled_errinj = fun.iter(errinj):
                           filter(function(i, x)
                               if x.is_enabled then
                                   return i
                               end
                           end):totable()
    log.info('Enabled fault injections: %s',
             json.encode(enabled_errinj))
    for _, errinj_name in pairs(enabled_errinj) do
        local errinj_val = errinj[errinj_name].disable(space)
        log.info('DISABLE ERROR INJECTION: %s', errinj_name)
        errinj[errinj_name].is_enabled = false
        pcall(box.error.injection.set, errinj_name, errinj_val)
    end
end

local function toggle_random_errinj(errinj, max_enabled, space)
    local enabled_errinj = fun.iter(errinj):
                           filter(function(i, x)
                               if x.is_enabled then
                                   return i
                               end
                           end):totable()
    log.info('Enabled fault injections: %s',
             json.encode(enabled_errinj))
    local errinj_val, errinj_name
    if table.getn(enabled_errinj) >= max_enabled then
        errinj_name = oneof(enabled_errinj)
        errinj_val = errinj[errinj_name].disable(space)
        errinj[errinj_name].is_enabled = false
    else
        errinj_name = oneof(keys(errinj))
        errinj_val = errinj[errinj_name].enable(space)
        errinj[errinj_name].is_enabled = true
    end
    log.info('TOGGLE RANDOM ERROR INJECTION: %s -> %s',
             errinj_name, tostring(errinj_val))
    local ok, err = pcall(box.error.injection.set, errinj_name, errinj_val)
    if not ok then
        log.info('Failed to toggle fault injection: %s', err)
    end
end

local enable_errinj_boolean = function(_space) return true end
local disable_errinj_boolean = function(_space) return false end
local enable_errinj_timeout = function(_space)
    return math.random(1, 3)
end
local disable_errinj_timeout = function(_space) return 0 end

-- Tarantool fault injections described in a table returned by
-- `box.error.injection.info()`. However, some fault injections
-- are not safe to use and could lead to false positive bugs.
-- The table below contains fault injections that are useful
-- in fuzzing testing, see details in [1].
--
-- 1. https://github.com/tarantool/tarantool/issues/10236#issuecomment-2225347088
local errinj_set = {
    -- Set to index id (0, 1, 2, ...) to fail index (re)build on
    -- alter.
    ERRINJ_BUILD_INDEX = {
        enable = function(space)
            return math.random(#(keys(space.index)))
        end,
        disable = function(_space)
            return -1
        end,
    },
    -- Set to true to inject delay during index (re)build on alter.
    ERRINJ_BUILD_INDEX_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to timeout in seconds to inject after each tuple
    -- processed on index (re)build on alter.
    ERRINJ_BUILD_INDEX_TIMEOUT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to true to inject delay during space format check on
    -- alter.
    ERRINJ_CHECK_FORMAT_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to inject OOM while allocating an index extend
    -- in memtx.
    ERRINJ_INDEX_ALLOC = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to number of passes before starting to fail primitive index data
    -- operations.
    ERRINJ_INDEX_OOM_COUNTDOWN = {
        enable = function()
            return math.random(100)
        end,
        disable = function()
            return -1
        end,
    },
    -- Set to true to fail index iterator creation.
    ERRINJ_INDEX_ITERATOR_NEW = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay freeing memory after dropped memtx
    -- index.
    ERRINJ_MEMTX_DELAY_GC = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay materialization of memtx snapshot.
    ERRINJ_SNAP_COMMIT_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay write of memtx snapshot.
    ERRINJ_SNAP_WRITE_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to timeout in seconds to inject after each tuple
    -- written to memtx snapshot.
    ERRINJ_SNAP_WRITE_TIMEOUT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to true to fail index select.
    ERRINJ_TESTING = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail allocation of memtx tuple.
    ERRINJ_TUPLE_ALLOC = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to timeout to inject before processing each internal
    -- cbus message.
    ERRINJ_TX_DELAY_PRIO_ENDPOINT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to true to fail reading vinyl page from disk.
    ERRINJ_VYRUN_DATA_READ = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay vinyl compaction.
    ERRINJ_VY_COMPACTION_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay lookup of tuple by full key.
    ERRINJ_VY_POINT_LOOKUP_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay vinyl dump.
    ERRINJ_VY_DUMP_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to disable vinyl garbage collection.
    ERRINJ_VY_GC = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to index id to fail vinyl index dump.
    ERRINJ_VY_INDEX_DUMP = {
        enable = function(space)
            return math.random(#space.index + 1) - 1
        end,
        disable = function()
            return -1
        end,
    },
    -- Set to true to fail materialization of vinyl index file.
    ERRINJ_VY_INDEX_FILE_RENAME = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail materialization of vinyl log file.
    ERRINJ_VY_LOG_FILE_RENAME = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail write to vinyl log file.
    ERRINJ_VY_LOG_FLUSH = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to inject delay before consuming vinyl memory quota.
    ERRINJ_VY_QUOTA_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail reading vinyl page from disk.
    ERRINJ_VY_READ_PAGE = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay reading vinyl page from disk.
    ERRINJ_VY_READ_PAGE_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to timeout to inject while reading vinyl page from disk.
    ERRINJ_VY_READ_PAGE_TIMEOUT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to true to fail read view merge during vinyl
    -- dump/compaction due to OOM.
    ERRINJ_VY_READ_VIEW_MERGE_FAIL = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to disable purging empty/failed run files from
    -- log after vinyl dump/compaction.
    ERRINJ_VY_RUN_DISCARD = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail materialization of vinyl run file.
    ERRINJ_VY_RUN_FILE_RENAME = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail vinyl run file write.
    ERRINJ_VY_RUN_WRITE = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay vinyl run file write.
    ERRINJ_VY_RUN_WRITE_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to timeout to inject after writing each tuple during
    -- vinyl dump/compaction.
    ERRINJ_VY_RUN_WRITE_STMT_TIMEOUT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to timeout to throttle scheduler for after failed vinyl
    -- dump/compaction.
    ERRINJ_VY_SCHED_TIMEOUT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to timeout to inject before squashing vinyl upsert in
    -- background.
    ERRINJ_VY_SQUASH_TIMEOUT = {
        enable = enable_errinj_timeout,
        disable = disable_errinj_timeout,
    },
    -- Set to number of passes before failing allocation of vinyl tuple.
    ERRINJ_VY_STMT_ALLOC_COUNTDOWN = {
        enable = function()
            return math.random(10)
        end,
        disable = function()
            return -1
        end,
    },
    -- Set to true to fail completion of vinyl dump/compaction.
    ERRINJ_VY_TASK_COMPLETE = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail creation of vinyl dump/compaction task
    -- due to OOM.
    ERRINJ_VY_WRITE_ITERATOR_START_FAIL = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to delay write to WAL.
    ERRINJ_WAL_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to number of failures before successful allocation of
    -- disk space for WAL write.
    ERRINJ_WAL_FALLOCATE = {
        enable = function()
            return math.random(10)
        end,
        disable = function()
            return 0
        end,
    },
    -- Set to true to fail WAL write.
    ERRINJ_WAL_IO = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail creation of new WAL file.
    ERRINJ_WAL_ROTATE = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail WAL sync.
    ERRINJ_WAL_SYNC = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to inject delay after WAL sync.
    ERRINJ_WAL_SYNC_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail write to xlog file.
    ERRINJ_WAL_WRITE = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to true to fail write to xlog file.
    ERRINJ_WAL_WRITE_DISK = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to number of bytes to buffer before failing write to xlog file.
    ERRINJ_WAL_WRITE_PARTIAL = {
        enable = function()
            return math.random(65536)
        end,
        disable = function()
            return -1
        end,
    },
    -- Set to true to fail xlog meta read.
    ERRINJ_XLOG_META = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
    -- Set to number of bytes to read before failing xlog data read.
    ERRINJ_XLOG_READ = {
        enable = function()
            return math.random(65536)
        end,
        disable = function()
            return -1
        end,
    },
    -- Set to true to delay xlog file materialization.
    ERRINJ_XLOG_RENAME_DELAY = {
        enable = enable_errinj_boolean,
        disable = disable_errinj_boolean,
    },
}

local function is_error_expected(err_msg, err_whitelist)
    local is_expected = false
    for _, err_pat in ipairs(err_whitelist) do
        if err_msg:match(err_pat) then
            is_expected = true
            break
        end
    end
    return is_expected
end

local function process_errors(error_messages)
    print('Unexpected errors:')
    local found_unexpected_errors = false
    for err_msg, _ in pairs(error_messages) do
        local is_expected = is_error_expected(err_msg, err_pat_whitelist)
        if not is_expected then
            found_unexpected_errors = true
            print(('\t- %s'):format(err_msg))
        end
    end
    if not found_unexpected_errors then
        print('None')
    end
    return found_unexpected_errors
end

local function start_error_injections(space, deadline)
    local errinj_f = fiber.new(function(deadline)
        log.info('Fault injection fiber has started.')
        local max_errinj_in_parallel = 5
        while os.clock() <= deadline do
            toggle_random_errinj(errinj_set, max_errinj_in_parallel, space)
            fiber.sleep(2)
        end
        disable_all_errinj(errinj_set, space)
        log.info('Fault injection fiber has finished.')
    end, deadline)
    errinj_f:set_joinable(true)
    errinj_f:name('ERRINJ')

    return errinj_f
end

local function run_test(num_workers, test_duration, test_dir,
                        engine_name, verbose_mode, fault_injection)
    if fio.path.exists(test_dir) then
        cleanup_dir(test_dir)
    else
        fio.mkdir(test_dir)
    end

    local socket_path = fio.pathjoin(fio.abspath(test_dir), 'console.sock')
    console.listen(socket_path)
    log.info('console listen on %s', socket_path)

    local fibers = {}
    local space_id_func = counter()
    local space = setup(engine_name, space_id_func, test_dir, verbose_mode)
    local deadline = os.clock() + test_duration

    local test_gen = fun.cycle(fun.iter(keys(ops)))
    local f
    for id = 1, num_workers do
        f = fiber.new(worker_func, id, space, test_gen, deadline)
        f:set_joinable(true)
        f:name('WRK #' .. id)
        table.insert(fibers, f)
    end

    if fault_injection then
        f = start_error_injections(space, deadline)
        table.insert(fibers, f)
    end

    local error_messages = {}
    for _, fb in ipairs(fibers) do
        local ok, res = fiber.join(fb)
        if not ok then
            log.info('ERROR: %s', json.encode(res))
        elseif res then
            for _, v in ipairs(res) do
                local msg = tostring(v)
                error_messages[msg] = error_messages[msg] or 1
            end
        end
    end

    teardown(space)

    local exit_code = process_errors(error_messages) and 1 or 0
    os.exit(exit_code)
end

run_test(arg_num_workers, arg_test_duration, arg_test_dir,
         arg_engine, arg_verbose, arg_fault_injection)
