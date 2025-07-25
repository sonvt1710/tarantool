-- schema.lua (internal file)
--
local ffi = require('ffi')
local msgpack = require('msgpack')
local msgpackffi = require('msgpackffi')
local fun = require('fun')
local log = require('log')
local buffer = require('buffer')
local fiber = require('fiber')
local session = box.session
local internal = box.internal
local utf8 = require('utf8')
local utils = require('internal.utils')
local compat = require('compat')

local check_param = utils.check_param
local check_param_table = utils.check_param_table
local update_param_table = utils.update_param_table
local call_at = utils.call_at

local DEFAULT_ORIGIN = ''
-- We use the field ID instead of the field name so we don't need to upgrade
-- the schema to use _origins option.
local PRIV_OPTS_FIELD_ID = 6

local function setmap(table)
    return setmetatable(table, { __serialize = 'map' })
end

local builtin = ffi.C

-- performance fixup for hot functions
local tuple_encode = box.internal.tuple.encode
local tuple_bless = box.internal.tuple.bless
local is_tuple = box.tuple.is
assert(tuple_encode ~= nil and tuple_bless ~= nil and is_tuple ~= nil)
local cord_ibuf_take = buffer.internal.cord_ibuf_take
local cord_ibuf_put = buffer.internal.cord_ibuf_put

local INT64_MIN = tonumber64('-9223372036854775808')
local INT64_MAX = tonumber64('9223372036854775807')

ffi.cdef[[
    extern bool box_read_ffi_is_disabled;
    extern bool memtx_tx_manager_use_mvcc_engine;
    struct space *space_by_id(uint32_t id);
    void space_run_triggers(struct space *space, bool yesno);
    size_t space_bsize(struct space *space);

    typedef struct tuple box_tuple_t;
    typedef struct iterator box_iterator_t;

    box_iterator_t *
    box_index_iterator_with_offset(uint32_t space_id, uint32_t index_id,
                                   int type, const char *key,
                                   const char *key_end,
                                   const char *packed_pos,
                                   const char *packed_pos_end,
                                   uint32_t offset);
    int
    box_iterator_next(box_iterator_t *itr, box_tuple_t **result);
    void
    box_iterator_free(box_iterator_t *itr);
    ssize_t
    box_index_len(uint32_t space_id, uint32_t index_id);
    ssize_t
    box_index_bsize(uint32_t space_id, uint32_t index_id);
    int
    box_index_quantile(uint32_t space_id, uint32_t index_id, double level,
                       const char *begin_key, const char *begin_key_end,
                       const char *end_key, const char *end_key_end,
                       const char **quantile_key,
                       const char **quantile_key_end);
    int
    box_index_random(uint32_t space_id, uint32_t index_id, uint32_t rnd,
                     box_tuple_t **result);
    int
    box_index_get(uint32_t space_id, uint32_t index_id, const char *key,
                  const char *key_end, box_tuple_t **result);
    int
    box_index_min(uint32_t space_id, uint32_t index_id, const char *key,
                  const char *key_end, box_tuple_t **result);
    int
    box_index_max(uint32_t space_id, uint32_t index_id, const char *key,
                  const char *key_end, box_tuple_t **result);
    ssize_t
    box_index_count(uint32_t space_id, uint32_t index_id, int type,
                    const char *key, const char *key_end);
    size_t
    box_region_used(void);
    void
    box_region_truncate(size_t size);
    bool
    box_txn();
    int64_t
    box_txn_id();
    int
    box_txn_isolation();
    int
    box_txn_begin();
    int
    box_txn_set_timeout(double timeout);
    void
    box_txn_make_sync();
    int
    box_sequence_current(uint32_t seq_id, int64_t *result);
    typedef struct txn_savepoint box_txn_savepoint_t;

    box_txn_savepoint_t *
    box_txn_savepoint();

    struct port {
        const struct port_vtab *vtab;
        char pad[74];
    };

    enum port_c_entry_type {
        PORT_C_ENTRY_UNKNOWN,
        PORT_C_ENTRY_NULL,
        PORT_C_ENTRY_DOUBLE,
        PORT_C_ENTRY_TUPLE,
        PORT_C_ENTRY_STR,
        PORT_C_ENTRY_BOOL,
        PORT_C_ENTRY_MP,
        PORT_C_ENTRY_MP_OBJECT,
        PORT_C_ENTRY_MP_ITERABLE,
    };

    struct port_c_iterator;

    typedef void
    (*port_c_iterator_create_f)(void *data, struct port_c_iterator *it);

    struct port_c_iterable {
        port_c_iterator_create_f iterator_create;
        void *data;
    };

    struct port_c_entry {
        struct port_c_entry *next;
        enum port_c_entry_type type;
        union {
            double number;
            struct tuple *tuple;
            bool boolean;
            struct {
                const char *data;
                uint32_t size;
            } str;
            struct {
                const char *data;
                uint32_t size;
                union {
                    struct tuple_format *mp_format;
                    struct mp_ctx *mp_ctx;
                };
            } mp;
            struct port_c_iterable iterable;
        };
    };

    struct port_c {
        const struct port_vtab *vtab;
        struct port_c_entry *first;
        struct port_c_entry *last;
        struct port_c_entry first_entry;
        int size;
    };

    void
    port_destroy(struct port *port);

    int
    box_index_tuple_position(uint32_t space_id, uint32_t index_id,
                             const char *tuple, const char *tuple_end,
                             const char **pos, const char **pos_end);

    int
    box_select_ffi(uint32_t space_id, uint32_t index_id, const char *key,
                   const char *key_end, const char **packed_pos,
                   const char **packed_pos_end, bool update_pos,
                   struct port *port, int64_t iterator, uint64_t offset,
                   uint64_t limit);

    enum priv_type {
        PRIV_R = 1,
        PRIV_W = 2,
        PRIV_X = 4,
        PRIV_S = 8,
        PRIV_U = 16,
        PRIV_C = 32,
        PRIV_D = 64,
        PRIV_A = 128,
        PRIV_REFERENCE = 256,
        PRIV_TRIGGER = 512,
        PRIV_INSERT = 1024,
        PRIV_UPDATE = 2048,
        PRIV_DELETE = 4096,
        PRIV_GRANT = 8192,
        PRIV_REVOKE = 16384,
        PRIV_ALL  = 4294967295
    };

]]

box.priv = {
    ["R"] = builtin.PRIV_R,
    ["W"] = builtin.PRIV_W,
    ["X"] = builtin.PRIV_X,
    ["S"] = builtin.PRIV_S,
    ["U"] = builtin.PRIV_U,
    ["C"] = builtin.PRIV_C,
    ["D"] = builtin.PRIV_D,
    ["A"] = builtin.PRIV_A,
    ["REFERENCE"] = builtin.PRIV_REFERENCE,
    ["TRIGGER"] = builtin.PRIV_TRIGGER,
    ["INSERT"] = builtin.PRIV_INSERT,
    ["UPDATE"] = builtin.PRIV_UPDATE,
    ["DELETE"] = builtin.PRIV_DELETE,
    ["GRANT"]= builtin.PRIV_GRANT,
    ["REVOKE"] = builtin.PRIV_REVOKE,
    ["ALL"] = builtin.PRIV_ALL
}

local function user_or_role_resolve(user)
    local _vuser = box.space[box.schema.VUSER_ID]
    local tuple
    if type(user) == 'string' then
        tuple = _vuser.index.name:get{user}
    else
        tuple = _vuser:get{user}
    end
    if tuple == nil then
        return nil
    end
    return tuple.id
end

local function role_resolve(name_or_id)
    local _vuser = box.space[box.schema.VUSER_ID]
    local tuple
    if type(name_or_id) == 'string' then
        tuple = _vuser.index.name:get{name_or_id}
    elseif type(name_or_id) ~= 'nil' then
        tuple = _vuser:get{name_or_id}
    end
    if tuple == nil or tuple.type ~= 'role' then
        return nil
    else
        return tuple.id
    end
end

local function user_resolve(name_or_id, level)
    local _vuser = box.space[box.schema.VUSER_ID]
    local tuple
    if type(name_or_id) == 'string' then
        tuple = _vuser.index.name:get{name_or_id}
    elseif type(name_or_id) ~= 'nil' then
        tuple = call_at(level + 1, _vuser.get, _vuser, {name_or_id})
    end
    if tuple == nil or tuple.type ~= 'user' then
        return nil
    else
        return tuple.id
    end
end

local function sequence_resolve(name_or_id)
    local _vsequence = box.space[box.schema.VSEQUENCE_ID]
    local tuple
    if type(name_or_id) == 'string' then
        tuple = _vsequence.index.name:get{name_or_id}
    elseif type(name_or_id) ~= 'nil' then
        tuple = _vsequence:get{name_or_id}
    end
    if tuple ~= nil then
        return tuple.id, tuple
    else
        return nil
    end
end

-- Revoke all privileges associated with the given object.
local function revoke_object_privs(object_type, object_id)
    local _vpriv = box.space[box.schema.VPRIV_ID]
    local _priv = box.space[box.schema.PRIV_ID]
    local privs = _vpriv.index.object:select{object_type, object_id}
    for _, tuple in pairs(privs) do
        local uid = tuple.grantee
        _priv:delete{uid, object_type, object_id}
    end
end

local function feedback_save_event(event)
    if internal.feedback_daemon ~= nil then
        internal.feedback_daemon.save_event(event)
    end
end

-- Public isolation level map string -> number.
box.txn_isolation_level = {
    ['default'] = 0,
    ['DEFAULT'] = 0,
    ['read-committed'] = 1,
    ['READ_COMMITTED'] = 1,
    ['read-confirmed'] = 2,
    ['READ_CONFIRMED'] = 2,
    ['best-effort'] = 3,
    ['BEST_EFFORT'] = 3,
    ['linearizable'] = 4,
    ['LINEARIZABLE'] = 4,
}

-- Create private isolation level map anything-correct -> number.
local function create_txn_isolation_level_map()
    local res = {}
    for k,v in pairs(box.txn_isolation_level) do
        res[k] = v
        res[v] = v
    end
    return res
end

-- Private isolation level map anything-correct -> number.
local txn_isolation_level_map = create_txn_isolation_level_map()
box.internal.txn_isolation_level_map = txn_isolation_level_map

-- Convert to numeric the value of txn isolation level, raise if failed.
local function normalize_txn_isolation_level(txn_isolation, level)
    txn_isolation = txn_isolation_level_map[txn_isolation]
    if txn_isolation == nil then
        box.error(box.error.ILLEGAL_PARAMS,
                  "txn_isolation must be one of box.txn_isolation_level" ..
                  " (keys or values)", level and level + 1)
    end
    return txn_isolation
end

box.internal.normalize_txn_isolation_level = normalize_txn_isolation_level

local begin_options = {
    timeout = function(timeout, level)
        if type(timeout) ~= "number" or timeout <= 0 then
            box.error(box.error.ILLEGAL_PARAMS,
                      "timeout must be a number greater than 0",
                      level + 1)
        end
        return true
    end,
    txn_isolation = normalize_txn_isolation_level,
    is_sync = function(is_sync, level)
        if type(is_sync) ~= "boolean" then
            box.error(box.error.ILLEGAL_PARAMS, "is_sync must be a boolean",
                      level + 1)
        end
        if is_sync == false then
            box.error(box.error.ILLEGAL_PARAMS, "is_sync can only be true",
                      level + 1)
        end
        return true
    end,
}

local atomic_options = table.copy(begin_options)
atomic_options.wait = function()
    -- Let it be checked in C.
    return true
end

local function box_begin_impl(options, level)
    local timeout
    local txn_isolation
    local is_sync
    if options then
        timeout = options.timeout
        txn_isolation = options.txn_isolation and
                        normalize_txn_isolation_level(options.txn_isolation)
        is_sync = options.is_sync
    end
    if builtin.box_txn_begin() == -1 then
        box.error(box.error.last(), level + 1)
    end
    if timeout then
        assert(builtin.box_txn_set_timeout(timeout) == 0)
    end
    if txn_isolation and
       internal.txn_set_isolation(txn_isolation) ~= 0 then
        box.rollback()
        box.error(box.error.last(), level + 1)
    end
    if is_sync then
        builtin.box_txn_make_sync()
    end
end

box.begin = function(options)
    check_param_table(options, begin_options, 2)
    box_begin_impl(options, 2)
end

box.is_in_txn = builtin.box_txn

box.txn_id = function()
    local id = builtin.box_txn_id()
    if -1 == id then
        return nil
    end
    return tonumber(id)
end

box.internal.txn_isolation = function()
    local lvl = builtin.box_txn_isolation()
    return lvl ~= -1 and lvl or nil
end

box.savepoint = function()
    local csavepoint = builtin.box_txn_savepoint()
    if csavepoint == nil then
        box.error(box.error.last(), 2)
    end
    return { csavepoint=csavepoint, txn_id=builtin.box_txn_id() }
end

local function atomic_tail(level, options, status, ...)
    local err
    if not status then
        err = ...
        goto fail
    end
    status, err = pcall(box.commit, options)
    if not status then
        goto fail
    end
    do return ... end

::fail::
    box.rollback()
    if box.error.is(err) then
        -- This will update box.error trace to proper value.
        box.error(err, level + 1)
    else
        -- Keep original trace and append trace of level + 1 as
        -- in case of box.error.
        error(tostring(err), level + 1)
    end
end

box.atomic = function(arg0, arg1, ...)
    -- There are two cases:
    -- 1. arg0 is a function (callable in general) while arg1,... are arguments.
    -- 2. arg0 is an options table, arg1 - a function and ... are arguments.
    -- The simplest way to distinguish that cases (without any other checks
    -- for correctness) is to check that arg0 is not a callable table.
    local arg0_is_noncallable_table = false
    if type(arg0) == 'table' then
        local mt = debug.getmetatable(arg0)
        arg0_is_noncallable_table = mt == nil or mt.__call == nil
    end
    local usage = 'Usage: box.atomic([opts, ]tx-function[, function-arguments]'
    if arg0_is_noncallable_table then
        if not utils.is_callable(arg1) then
            box.error(box.error.ILLEGAL_PARAMS, usage, 2)
        end
        local options = arg0
        check_param_table(options, atomic_options, 2)
        box_begin_impl(options, 2)
        return atomic_tail(1, options, pcall(arg1, ...))
    else
        if not utils.is_callable(arg0) then
            box.error(box.error.ILLEGAL_PARAMS, usage, 2)
        end
        box.begin()
        return atomic_tail(1, nil, pcall(arg0, arg1, ...))
    end
end

-- Wrap a function into transaction if none is active.
local function atomic_wrapper(func)
    return function(...)
        utils.box_check_configured(2)
        -- No reason to start a transaction if one is active already.
        if box.is_in_txn() then
            return func(...)
        else
            return box.atomic(func, ...)
        end
    end
end

-- box.commit yields, so it's defined as Lua/C binding
-- box.rollback and box.rollback_to_savepoint yields as well

-- Check and normalize constraint definition.
-- Given constraint @a constr is expected to be either a func name or
--  a table with function names and/or consraint name:function name pairs.
-- In case of error box.error.ILLEGAL_PARAMS is raised, and @a error_prefix
--  is added before string message.
local function normalize_constraint(constr, error_prefix, level)
    if type(constr) == 'string' then
        -- Short form of field constraint - just name of func,
        -- e.g.: {...constraint = "func_name"}
        local found = box.space._func.index.name:get(constr)
        if not found then
            box.error(box.error.ILLEGAL_PARAMS,
                      error_prefix .. "constraint function " ..
                      "was not found by name '" .. constr .. "'", level + 1)
        end
        -- normalize form of constraint.
        return {[constr] = found.id}
    elseif type(constr) == 'table' then
        -- Long form of field constraint - a table with:
        -- 1) func names 2) constraint name -> func name pairs.
        -- e.g.: {..., constraint = {func1, name2 = func2, ...}}
        local result = {}
        for constr_key, constr_func in pairs(constr) do
            if type(constr_func) ~= 'string' then
                box.error(box.error.ILLEGAL_PARAMS,
                          error_prefix .. "constraint function " ..
                          "is expected to be a string, " ..
                          "but got " .. type(constr_func), level + 1)
            end
            local found = box.space._func.index.name:get(constr_func)
            if not found then
                box.error(box.error.ILLEGAL_PARAMS,
                          error_prefix .. "constraint function " ..
                          "was not found by name '" .. constr_func .. "'",
                          level + 1)
            end
            local constr_name = nil
            if type(constr_key) == 'number' then
                -- 1) func name only.
                constr_name = constr_func
            elseif type(constr_key) == 'string' then
                -- 2) constraint name + func name pair.
                constr_name = constr_key
            else
                -- what are you?
                box.error(box.error.ILLEGAL_PARAMS,
                          error_prefix .. "constraint name " ..
                          "is expected to be a string, " ..
                          "but got " .. type(constr_key), level + 1)
            end
            -- normalize form of constraint pair.
            result[constr_name] = found.id
        end
        -- return normalized form of constraints.
        return result
    elseif constr then
        -- unrecognized form of constraint.
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "constraint must be string or table",
                  level + 1)
    end
    return nil
end

-- Helper of normalize_foreign_key.
-- Check and normalize one foreign key definition.
-- If not is_complex, field is expected to be a numeric ID or string name of
--  foreign field.
-- If is_complex, field is expected to be a table with local field ->
--  foreign field mapping.
-- If fkey_same_space, the foreign key refers to the same space.
local function normalize_foreign_key_one(def, error_prefix, is_complex,
                                         fkey_same_space, level)
    if def.field == nil then
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "foreign key: field must be specified",
                  level + 1)
    end
    if def.space ~= nil and
       type(def.space) ~= 'string' and type(def.space) ~= 'number' then
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "foreign key: space must be string or number",
                  level + 1)
    end
    local field = def.field
    if not is_complex then
        if type(field) ~= 'string' and type(field) ~= 'number' then
            box.error(box.error.ILLEGAL_PARAMS,
                      error_prefix ..
                      "foreign key: field must be string or number",
                      level + 1)
        end
        if type(field) == 'number' then
            -- convert to zero-based index.
            field = field - 1
        end
    else
        if type(field) ~= 'table' then
            box.error(box.error.ILLEGAL_PARAMS,
                      error_prefix .. "foreign key: field must be a table " ..
                      "with local field -> foreign field mapping", level + 1)
        end
        local count = 0
        local converted = {}
        for k,v in pairs(field) do
            count = count + 1
            if type(k) ~= 'string' and type(k) ~= 'number' then
                box.error(box.error.ILLEGAL_PARAMS,
                          error_prefix .. "foreign key: local field must be "
                          .. "string or number", level + 1)
            end
            if type(k) == 'number' then
                -- convert to zero-based index.
                k = k - 1
            end
            if type(v) ~= 'string' and type(v) ~= 'number' then
                box.error(box.error.ILLEGAL_PARAMS,
                          error_prefix .. "foreign key: foreign field must be "
                          .. "string or number", level + 1)
            end
            if type(v) == 'number' then
                -- convert to zero-based index.
                v = v - 1
            end
            converted[k] = v
        end
        if count < 1 then
            box.error(box.error.ILLEGAL_PARAMS,
                      error_prefix .. "foreign key: field must be a table " ..
                      "with local field -> foreign field mapping", level + 1)
        end
        field = setmap(converted)
    end
    if not box.space[def.space] and not fkey_same_space then
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "foreign key: space " .. tostring(def.space)
                  .. " was not found", level + 1)
    end
    for k in pairs(def) do
        if k ~= 'space' and k ~= 'field' then
            box.error(box.error.ILLEGAL_PARAMS, error_prefix ..
                      "foreign key: unexpected parameter '" ..
                      tostring(k) .. "'", level + 1)
        end
    end
    if fkey_same_space then
        return {field = field}
    else
        return {space = box.space[def.space].id, field = field}
    end
end

-- Check and normalize foreign key definition.
-- Given definition @a fkey is expected to be one of:
-- {space=.., field=..}
-- {fkey_name={space=.., field=..}, }
-- If not is_complex, field is expected to be a numeric ID or string name of
--  foreign field.
-- If is_complex, field is expected to be a table with local field ->
--  foreign field mapping.
-- @a space_id and @a space_name - ID and name of a space, which contains the
--  foreign key.
-- In case of error box.error.ILLEGAL_PARAMS is raised, and @a error_prefix
--  is added before string message.
local function normalize_foreign_key(space_id, space_name, fkey, error_prefix,
                                     is_complex, level)
    if fkey == nil then
        return nil
    end
    if type(fkey) ~= 'table' then
        -- unrecognized form
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "foreign key must be a table", level + 1)
    end
    if fkey.field ~= nil and
        (type(fkey.space) ~= 'table' or type(fkey.field) ~= 'table') then
        -- the first, short form.
        local fkey_same_space = (fkey.space == nil or
                                 fkey.space == space_id or
                                 fkey.space == space_name)
        fkey = normalize_foreign_key_one(fkey, error_prefix, is_complex,
                                         fkey_same_space, level)
        local fkey_name = fkey_same_space and (space_name or 'unknown') or
                          box.space[fkey.space].name
        return {[fkey_name] = fkey}
    end
    -- the second, detailed form.
    local result = {}
    for k,v in pairs(fkey) do
        if type(k) ~= 'string' then
            box.error(box.error.ILLEGAL_PARAMS,
                      error_prefix .. "foreign key name must be a string",
                      level + 1)
        end
        if type(v) ~= 'table' then
            -- unrecognized form
            box.error(box.error.ILLEGAL_PARAMS,
                      error_prefix .. "foreign key definition must be a table "
                      .. "with 'space' and 'field' members", level + 1)
        end
        local fkey_same_space = (v.space == nil or
                                 v.space == space_id or
                                 v.space == space_name)
        v = normalize_foreign_key_one(v, error_prefix, is_complex,
                                      fkey_same_space, level)
        result[k] = v
    end
    return result
end

-- Check and normalize field default function.
local function normalize_default_func(func_name, error_prefix, level)
    if type(func_name) ~= 'string' then
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "field default function name is expected " ..
                  "to be a string, but got " .. type(func_name), level + 1)
    end
    local found = box.space._func.index.name:get(func_name)
    if not found then
        box.error(box.error.ILLEGAL_PARAMS,
                  error_prefix .. "field default function was not found by " ..
                  "name '" .. func_name .. "'", level + 1)
    end
    return found.id
end

local function normalize_format(space_id, space_name, format, level)
    local result = {}
    for i, given in ipairs(format) do
        local field = {}
        if type(given) ~= "table" then
            field.name = given
        else
            for k, v in pairs(given) do
                if k == 1 then
                    if given.name then
                        if not given.type then
                            field.type = v
                        else
                            field[1] = v
                        end
                    else
                        field.name = v
                    end
                elseif k == 2 and not given.type and not given.name then
                    field.type = v
                elseif k == 'collation' then
                    local coll = box.space._collation.index.name:get{v}
                    if not coll then
                        box.error(box.error.ILLEGAL_PARAMS,
                            "format[" .. i .. "]: collation " ..
                            "was not found by name '" .. v .. "'",
                            level + 1)
                    end
                    field[k] = coll.id
                elseif k == 'constraint' then
                    field[k] = normalize_constraint(v, "format[" .. i .. "]: ",
                                                    level + 1)
                elseif k == 'foreign_key' then
                    field[k] = normalize_foreign_key(space_id, space_name,
                                                     v, "format[" .. i .. "]: ",
                                                     false,
                                                     level + 1)
                elseif k == 'default_func' then
                    field[k] = normalize_default_func(v,
                                                      "format[" .. i .. "]: ",
                                                      level + 1)
                else
                    field[k] = v
                end
            end
        end
        if type(field.name) ~= 'string' then
            box.error(box.error.ILLEGAL_PARAMS,
                      "format[" .. i .. "]: name (string) is expected",
                      level + 1)
        end
        if field.type == nil then
            field.type = 'any'
        elseif type(field.type) ~= 'string' then
            box.error(box.error.ILLEGAL_PARAMS,
                      "format[" .. i .. "]: type must be a string",
                      level + 1)
        end
        table.insert(result, field)
    end
    return result
end

-- for space.upgrade and box.tuple.format.new
box.internal.space.normalize_format = normalize_format

local function denormalize_foreign_key_one(fkey)
    assert(type(fkey.field) == 'string' or type(fkey.field) == 'number')
    local result = fkey
    if type(fkey.field) == 'number' then
        -- convert to one-based index
        result.field = result.field + 1
    end
    return result
end

local function denormalize_foreign_key(fkey)
    local result = setmap{}
    for k, v in pairs(fkey) do
        result[k] = denormalize_foreign_key_one(v)
    end
    return result
end

-- Convert zero-based foreign key field numbers to one-based
local function denormalize_format(format)
    local result = setmetatable({}, { __serialize = 'seq' })
    for i, f in ipairs(format) do
        result[i] = f
        for k, v in pairs(f) do
            if k == 'foreign_key' then
                result[i][k] = denormalize_foreign_key(v)
            end
        end
    end
    return result
end

box.internal.space.denormalize_format = denormalize_format

local space_types = {
    'normal',
    'data-temporary',
    'temporary',
}
local function check_space_type(space_type, level)
    if space_type == nil then
        return
    end
    for _, t in ipairs(space_types) do
        if t == space_type then
            return
        end
    end
    box.error(box.error.ILLEGAL_PARAMS,
              "unknown space type, must be one of: '" ..
              table.concat(space_types, "', '") .. "'.", level + 1)
end

box.schema.space = {}
box.schema.space.create = function(name, options)
    utils.box_check_configured(2)
    check_param(name, 'name', 'string', 2)
    local options_template = {
        if_not_exists = 'boolean',
        engine = 'string',
        id = 'number',
        field_count = 'number',
        user = 'string, number',
        format = 'table',
        type = 'string',
        is_local = 'boolean',
        temporary = 'boolean',
        is_sync = 'boolean',
        defer_deletes = 'boolean',
        constraint = 'string, table',
        foreign_key = 'table',
    }
    local options_defaults = {
        engine = 'memtx',
        field_count = 0,
    }
    check_param_table(options, options_template, 2)
    options = update_param_table(options, options_defaults)
    check_space_type(options.type, 2)
    if options.type ~= nil and options.temporary ~= nil then
        box.error(box.error.ILLEGAL_PARAMS,
                  "only one of 'type' or 'temporary' may be specified", 2)
    end
    if options.engine == 'vinyl' then
        options = update_param_table(options, {
            defer_deletes = box.cfg.vinyl_defer_deletes,
        })
    end

    local _space = box.space[box.schema.SPACE_ID]
    if box.space[name] then
        if options.if_not_exists then
            return box.space[name], "not created"
        else
            box.error(box.error.SPACE_EXISTS, name, 2)
        end
    end
    local id = options.id
    if not id then
        id = internal.generate_space_id(options.type == 'temporary')
    end
    local uid = session.euid()
    if options.user then
        uid = user_or_role_resolve(options.user)
        if uid == nil then
            box.error(box.error.NO_SUCH_USER, options.user, 2)
        end
    end
    local format = options.format and options.format or {}
    check_param(format, 'format', 'table', 2)
    format = normalize_format(id, name, format, 2)
    local constraint = normalize_constraint(options.constraint, '', 2)
    local foreign_key = normalize_foreign_key(id, name, options.foreign_key, '',
                                              true, 2)
    -- filter out global parameters from the options array
    local space_options = setmap({
        group_id = options.is_local and 1 or nil,
        temporary = options.temporary,
        type = options.type,
        is_sync = options.is_sync,
        defer_deletes = options.defer_deletes and true or nil,
        constraint = constraint,
        foreign_key = foreign_key,
    })
    call_at(2, _space.insert, _space,
            {id, uid, name, options.engine, options.field_count, space_options,
             format})

    feedback_save_event('create_space')
    return box.space[id], "created"
end

-- space format - the metadata about space fields
function box.schema.space.format(id, format)
    utils.box_check_configured(2)
    local _space = box.space._space
    local _vspace = box.space._vspace
    check_param(id, 'id', 'number', 2)

    local tuple = _vspace:get(id)
    if tuple == nil then
        box.error(box.error.NO_SUCH_SPACE, '#' .. tostring(id), 2)
    end

    if format == nil then
        return denormalize_format(tuple.format)
    else
        check_param(format, 'format', 'table', 2)
        format = normalize_format(id, tuple.name, format, 2)
        call_at(2, _space.update, _space, id, {{'=', 7, format}})
    end
end

function box.schema.space.upgrade(id)
    check_param(id, 'id', 'number', 2)
    box.error(box.error.UNSUPPORTED, "Community edition", "space upgrade", 2)
end

box.schema.create_space = box.schema.space.create

box.schema.space.drop = atomic_wrapper(function(space_id, space_name, opts)
    check_param(space_id, 'space_id', 'number', 2)
    opts = opts or {}
    check_param_table(opts, { if_exists = 'boolean' }, 2)
    local _space = box.space[box.schema.SPACE_ID]
    local _index = box.space[box.schema.INDEX_ID]
    local _trigger = box.space[box.schema.TRIGGER_ID]
    local _vindex = box.space[box.schema.VINDEX_ID]
    local _truncate = box.space[box.schema.TRUNCATE_ID]
    local _space_sequence = box.space[box.schema.SPACE_SEQUENCE_ID]
    local _func_index = box.space[box.schema.FUNC_INDEX_ID]
    -- This is needed to support dropping temporary spaces
    -- in read-only mode, because sequences aren't supported for them yet
    -- and therefore such requests aren't allowed in read-only mode.
    if _space_sequence:get(space_id) ~= nil then
        local sequence_tuple = _space_sequence:delete{space_id}
        if sequence_tuple.is_generated == true then
            -- Delete automatically generated sequence.
            box.schema.sequence.drop(sequence_tuple.sequence_id)
        end
    end
    for _, t in _trigger.index.space_id:pairs({space_id}) do
        _trigger:delete({t.name})
    end
    for _, t in _func_index.index.primary:pairs({space_id}) do
        _func_index:delete({space_id, t.index_id})
    end
    local keys = _vindex:select(space_id)
    for i = #keys, 1, -1 do
        local v = keys[i]
        _index:delete{v.id, v.iid}
    end
    revoke_object_privs('space', space_id)
    -- Deleting from _truncate currently adds a delete entry into WAL even
    -- if the corresponding space was never truncated. This is a problem for
    -- temporary spaces, because in such situations it's impossible to
    -- filter out such entries from the within on_replace trigger which
    -- basically results in temporary space's metadata getting into WAL
    -- which breaks some invariants.
    if _truncate:get{space_id} ~= nil then
        _truncate:delete{space_id}
    end
    if _space:delete{space_id} == nil then
        if space_name == nil then
            space_name = '#'..tostring(space_id)
        end
        if not opts.if_exists then
            box.error(box.error.NO_SUCH_SPACE, space_name, 2)
        end
    end

    feedback_save_event('drop_space')
end)

box.schema.space.rename = function(space_id, space_name)
    utils.box_check_configured(2)
    check_param(space_id, 'space_id', 'number', 2)
    check_param(space_name, 'space_name', 'string', 2)

    local _space = box.space[box.schema.SPACE_ID]
    call_at(2, _space.update, _space, space_id, {{"=", 3, space_name}})
end

local alter_space_template = {
    field_count = 'number',
    user = 'string, number',
    format = 'table',
    type = 'string',
    temporary = 'boolean',
    is_sync = 'boolean',
    defer_deletes = 'boolean',
    name = 'string',
    constraint = 'string, table',
    foreign_key = 'table',
}

box.schema.space.alter = function(space_id, options)
    utils.box_check_configured(2)
    local space = box.space[space_id]
    if not space then
        box.error(box.error.NO_SUCH_SPACE, '#'..tostring(space_id), 2)
    end
    check_param_table(options, alter_space_template, 2)

    local _space = box.space._space
    local tuple = _space:get({space.id})
    assert(tuple ~= nil)

    local owner
    if options.user then
        owner = user_or_role_resolve(options.user)
        if not owner then
            box.error(box.error.NO_SUCH_USER, options.user, 2)
        end
    else
        owner = tuple.owner
    end

    local name = options.name or tuple.name
    local field_count = options.field_count or tuple.field_count
    local flags = tuple.flags

    if options.type ~= nil then
        check_space_type(options.type, 2)
        flags.type = options.type
    end

    if options.temporary ~= nil then
        flags.temporary = options.temporary
    end

    if options.is_sync ~= nil then
        flags.is_sync = options.is_sync
    end

    if options.defer_deletes ~= nil then
        flags.defer_deletes = options.defer_deletes
    end

    local format
    if options.format ~= nil then
        format = normalize_format(space_id, tuple.name, options.format, 2)
    else
        format = tuple.format
    end

    if options.constraint ~= nil then
        if table.equals(options.constraint, {}) then
            options.constraint = nil
        end
        flags.constraint = normalize_constraint(options.constraint, '', 2)
    end

    if options.foreign_key ~= nil then
        if table.equals(options.foreign_key, {}) then
            options.foreign_key = nil
        end
        flags.foreign_key = normalize_foreign_key(space_id, name,
                                                  options.foreign_key, '', true,
                                                  2)
    end

    tuple = tuple:totable()
    tuple[2] = owner
    tuple[3] = name
    tuple[5] = field_count
    tuple[6] = flags
    tuple[7] = format
    call_at(2, _space.replace, _space, tuple)
end

box.schema.index = {}

local function update_index_parts_1_6_0(parts, level)
    local result = {}
    if #parts % 2 ~= 0 then
        box.error(box.error.ILLEGAL_PARAMS,
                  "options.parts: expected field_no (number), type (string) pairs",
                  level + 1)
    end
    local i = 0
    for _ in pairs(parts) do
        i = i + 1
        if parts[i] == nil then
            box.error(box.error.ILLEGAL_PARAMS,
                      "options.parts: expected field_no (number), type (string) pairs",
                      level + 1)
        end
        if i % 2 == 0 then
            goto continue
        end
        if type(parts[i]) ~= "number" then
            box.error(box.error.ILLEGAL_PARAMS,
                      "options.parts: expected field_no (number), type (string) pairs",
                      level + 1)
        elseif parts[i] == 0 then
            -- Lua uses one-based field numbers but _space is zero-based
            box.error(box.error.ILLEGAL_PARAMS,
                      "invalid index parts: field_no must be one-based",
                      level + 1)
        end
        if type(parts[i + 1]) ~= "string" then
            box.error(box.error.ILLEGAL_PARAMS,
                      "options.parts: expected field_no (number), type (string) pairs")
        end
        table.insert(result, {field = parts[i], type = parts[i + 1]})
        ::continue::
    end
    return result
end

--
-- Get field index by format field name.
--
local function format_field_index_by_name(format, name)
    for k, v in pairs(format) do
        if v.name == name then
            return k
        end
    end
    return nil
end

--
-- Get field 0-based index and relative JSON path to data by
-- field 1-based index or full JSON path. A particular case of a
-- full JSON path is the format field name.
--
local function format_field_resolve(format, path, what, level)
    assert(type(path) == 'number' or type(path) == 'string')
    local idx
    local relative_path = nil
    local field_name
    -- Path doesn't require resolve.
    if type(path) == 'number' then
        idx = path
        goto done
    end
    -- An attempt to interpret a path as the full field name.
    idx = format_field_index_by_name(format, path)
    if idx ~= nil then
        relative_path = nil
        goto done
    end
    -- Check if the initial part of the JSON path is a token of
    -- the form [%d].
    field_name = string.match(path, "^%[(%d+)%]")
    idx = tonumber(field_name)
    if idx ~= nil then
        relative_path = string.sub(path, string.len(field_name) + 3)
        goto done
    end
    -- Check if the initial part of the JSON path is a token of
    -- the form ["%s"] or ['%s'].
    field_name = string.match(path, '^%["([^%]]+)"%]') or
                 string.match(path, "^%['([^%]]+)'%]")
    idx = format_field_index_by_name(format, field_name)
    if idx ~= nil then
        relative_path = string.sub(path, string.len(field_name) + 5)
        goto done
    end
    -- Check if the initial part of the JSON path is a string
    -- token: assume that it ends with .*[ or .*.
    field_name = string.match(path, "^([^.[]+)")
    idx = format_field_index_by_name(format, field_name)
    if idx ~= nil then
        relative_path = string.sub(path, string.len(field_name) + 1)
        goto done
    end
    -- Can't resolve field index by path.
    assert(idx == nil)
    box.error(box.error.ILLEGAL_PARAMS, what .. ": " ..
              "field was not found by name '" .. path .. "'", level + 1)

::done::
    if idx <= 0 then
        box.error(box.error.ILLEGAL_PARAMS, what .. ": " ..
                  "field (number) must be one-based", level + 1)
    end
    return idx - 1, relative_path
end

local function update_index_parts(format, parts, level)
    if type(parts) ~= "table" then
        box.error(box.error.ILLEGAL_PARAMS,
        "options.parts parameter should be a table", level + 1)
    end
    if #parts == 0 then
        box.error(box.error.ILLEGAL_PARAMS,
        "options.parts must have at least one part", level + 1)
    end
    if type(parts[1]) == 'number' and
            (parts[2] == nil or type(parts[2]) == 'string') then
        if parts[3] == nil then
            parts = {parts} -- one part only
        else
            parts = update_index_parts_1_6_0(parts, 2, level + 1)
        end
    end

    local result = {}
    local i = 0
    for _ in pairs(parts) do
        i = i + 1
        if parts[i] == nil then
            box.error(box.error.ILLEGAL_PARAMS,
                    "options.parts: unexpected option(s)", level + 1)
        end
        local part = {}
        if type(parts[i]) ~= "table" then
            part.field = parts[i]
        else
            for k, v in pairs(parts[i]) do
                -- Support {1, 'unsigned', collation='xx'} shortcut
                if k == 1 or k == 'field' then
                    part.field = v;
                elseif k == 2 or k == 'type' then
                    part.type = v;
                elseif k == 'collation' then
                    -- find ID by name
                    local coll = box.space._collation.index.name:get{v}
                    if not coll then
                        coll = box.space._collation.index.name:get{v:lower()}
                    end
                    if not coll then
                        box.error(box.error.ILLEGAL_PARAMS,
                            "options.parts[" .. i .. "]: collation was not " ..
                            "found by name '" .. v .. "'", level + 1)
                    end
                    part[k] = coll[1]
                elseif k == 'is_nullable' then
                    part[k] = v
                elseif k == 'exclude_null' then
                    if type(v) ~= 'boolean' then
                        box.error(box.error.ILLEGAL_PARAMS,
                                "options.parts[" .. i .. "]: " ..
                                "type (boolean) is expected", level + 1)
                    end
                    part[k] = v
                else
                    part[k] = v
                end
            end
        end
        if type(part.field) == 'number' or type(part.field) == 'string' then
            local idx, path = format_field_resolve(format, part.field,
                                                   "options.parts[" .. i .. "]",
                                                   level + 1)
            part.field = idx
            part.path = path or part.path
        else
            box.error(box.error.ILLEGAL_PARAMS, "options.parts[" .. i .. "]: " ..
                      "field (name or number) is expected", level + 1)
        end
        local fmt = format[part.field + 1]
        if part.type == nil then
            if fmt and fmt.type then
                part.type = fmt.type
            else
                part.type = 'scalar'
            end
        elseif type(part.type) ~= 'string' then
            box.error(box.error.ILLEGAL_PARAMS,
                      "options.parts[" .. i .. "]: type (string) is expected",
                      level + 1)
        end
        if fmt then
           if part.scale == nil then
               part.scale = fmt.scale
           end
        end
        if part.collation == nil and fmt then
            part.collation = fmt.collation
        end
        if part.is_nullable == nil then
            if fmt and fmt.is_nullable then
                part.is_nullable = true
            end
        elseif type(part.is_nullable) ~= 'boolean' then
            box.error(box.error.ILLEGAL_PARAMS,
                      "options.parts[" .. i .. "]: type (boolean) is expected",
                      level + 1)
        end
        if (not part.is_nullable) and part.exclude_null then
            if part.is_nullable ~= nil then
                box.error(box.error.ILLEGAL_PARAMS,
                          "options.parts[" .. i .. "]: exclude_null=true " ..
                          "and is_nullable=false are incompatible", level + 1)
            end
            part.is_nullable = true
        end
        if part.action == nil then
            if fmt and fmt.action ~= nil then
                part.action = fmt.action
            end
        end
        if type(parts[i]) == "table" then
            local first_illegal_index = 3
            if parts[i].field ~= nil then
                first_illegal_index = first_illegal_index - 1
            end
            if parts[i].type ~= nil then
                first_illegal_index = first_illegal_index - 1
            end
            if parts[i][first_illegal_index] ~= nil then
                box.error(box.error.ILLEGAL_PARAMS,
                          "options.parts[" .. i .. "]: unexpected option " ..
                          parts[i][first_illegal_index], level + 1)
            end
        end
        table.insert(result, part)
    end
    return result
end

--
-- Convert index parts into 1.6.6 format if they
-- don't use any extra option beside type and field.
--
local function try_simplify_index_parts(parts)
    local new_parts = {}
    for i, part in pairs(parts) do
        for k in pairs(part) do
            if k ~= 'field' and k ~= 'type' then
                return parts
            end
        end
        new_parts[i] = {part.field, part.type}
    end
    return new_parts
end

--
-- Raise an error if a sequence isn't compatible with a given
-- index definition.
--
local function space_sequence_check(sequence, parts, space_name, index_name,
                                    level)
    local sequence_part = nil
    if sequence.field ~= nil then
        sequence.path = sequence.path or ''
        -- Look up the index part corresponding to the given field.
        for _, part in ipairs(parts) do
            local field = part.field or part[1]
            local path = part.path or ''
            if sequence.field == field and sequence.path == path then
                sequence_part = part
                break
            end
        end
        if sequence_part == nil then
            box.error(box.error.MODIFY_INDEX, index_name, space_name,
                      "sequence field must be a part of the index", level + 1)
        end
    else
        -- If the sequence field is omitted, use the first
        -- indexed field.
        sequence_part = parts[1]
        sequence.field = sequence_part.field or sequence_part[1]
        sequence.path = sequence_part.path or ''
    end
    -- Check the type of the auto-increment field.
    local t = sequence_part.type or sequence_part[2]
    if t ~= 'integer' and t ~= 'unsigned' then
        box.error(box.error.MODIFY_INDEX, index_name, space_name,
                  "sequence cannot be used with a non-integer key",
                  level + 1)
    end
end

--
-- The first stage of a space sequence modification operation. Called
-- before altering the space definition. Checks sequence options and
-- returns a proxy object that is supposed to be passed to the
-- space_sequence_alter_commit() to complete the operation.
--
local function space_sequence_alter_prepare(format, parts, options,
                                            space_id, index_id,
                                            space_name, index_name, level)
    local _space_sequence = box.space[box.schema.SPACE_SEQUENCE_ID]

    -- A sequence can only be attached to a primary index.
    if index_id ~= 0 then
        -- Ignore 'sequence = false' for secondary indexes.
        if not options.sequence then
            return nil
        end
        box.error(box.error.MODIFY_INDEX, index_name, space_name,
                  "sequence cannot be used with a secondary key", level + 1)
    end

    -- Look up the currently attached sequence, if any.
    local old_sequence
    local tuple = _space_sequence:get(space_id)
    if tuple ~= nil then
        old_sequence = {
            id = tuple.sequence_id,
            is_generated = tuple.is_generated,
            field = tuple.field,
            path = tuple.path,
        }
    else
        old_sequence = nil
    end

    if options.sequence == nil then
        -- No sequence option, just check that the old sequence
        -- is compatible with the new index definition.
        if old_sequence ~= nil and old_sequence.field ~= nil then
            space_sequence_check(old_sequence, parts, space_name, index_name,
                                 level + 1)
        end
        return nil
    end

    -- Convert the provided option to the table format.
    local new_sequence
    if type(options.sequence) == 'table' then
        -- Sequence is given as a table, just copy it.
        -- Silently ignore unknown fields.
        new_sequence = {
            id = options.sequence.id,
            field = options.sequence.field,
        }
    elseif options.sequence == true then
        -- Create an auto-generated sequence.
        new_sequence = {}
    elseif options.sequence == false then
        -- Drop the currently attached sequence.
        new_sequence = nil
    else
        -- Attach a sequence with the given id.
        new_sequence = {id = options.sequence}
    end

    if new_sequence ~= nil then
        -- Resolve the sequence name.
        if new_sequence.id ~= nil then
            local id = sequence_resolve(new_sequence.id)
            if id == nil then
                box.error(box.error.NO_SUCH_SEQUENCE, new_sequence.id,
                          level + 1)
            end
            local tuple = _space_sequence.index.sequence:select(id)[1]
            if tuple ~= nil and tuple.is_generated then
                box.error(box.error.ALTER_SPACE, space_name,
                          "can not attach generated sequence", level + 1)
            end
            new_sequence.id = id
        end
        -- Resolve the sequence field.
        if new_sequence.field ~= nil then
            local field, path = format_field_resolve(format, new_sequence.field,
                                                     "sequence field",
                                                     level + 1)
            new_sequence.field = field
            new_sequence.path = path
        end
        -- Inherit omitted options from the attached sequence.
        if old_sequence ~= nil then
            if new_sequence.id == nil and old_sequence.is_generated then
                new_sequence.id = old_sequence.id
                new_sequence.is_generated = true
            end
            if new_sequence.field == nil then
                new_sequence.field = old_sequence.field
                new_sequence.path = old_sequence.path
            end
        end
        -- Check that the sequence is compatible with
        -- the index definition.
        space_sequence_check(new_sequence, parts, space_name, index_name,
                             level + 1)
        -- If sequence id is omitted, we are supposed to create
        -- a new auto-generated sequence for the given space.
        if new_sequence.id == nil then
            local seq = box.schema.sequence.create(space_name .. '_seq')
            new_sequence.id = seq.id
            new_sequence.is_generated = true
        end
        new_sequence.is_generated = new_sequence.is_generated or false
    end

    return {
        space_id = space_id,
        new_sequence = new_sequence,
        old_sequence = old_sequence,
    }
end

--
-- The second stage of a space sequence modification operation. Called after
-- altering the space definition. Detaches the old sequence from the space and
-- attaches the new one to it. Drops the old sequence if required. 'proxy' is
-- an object returned by space_sequence_alter_prepare().
--
local function space_sequence_alter_commit(proxy)
    local _space_sequence = box.space[box.schema.SPACE_SEQUENCE_ID]

    if proxy == nil then
        -- No sequence option, nothing to do.
        return
    end

    local space_id = proxy.space_id
    local old_sequence = proxy.old_sequence
    local new_sequence = proxy.new_sequence

    if old_sequence ~= nil then
        _space_sequence:delete(space_id)
    end

    if new_sequence ~= nil then
        -- Attach the new sequence.
        _space_sequence:insert{space_id, new_sequence.id,
                               new_sequence.is_generated,
                               new_sequence.field, new_sequence.path}
    end

    if old_sequence ~= nil and old_sequence.is_generated and
       (new_sequence == nil or old_sequence.id ~= new_sequence.id) then
        -- Drop automatically generated sequence.
        box.schema.sequence.drop(old_sequence.id)
    end
end

-- Historically, some properties of an index
-- are stored as tuple fields, others in a
-- single field containing msgpack map.
-- This is the map.
local index_options = {
    unique = 'boolean',
    dimension = 'number',
    distance = 'string',
    run_count_per_level = 'number',
    run_size_ratio = 'number',
    range_size = 'number',
    page_size = 'number',
    bloom_fpr = 'number',
    func = 'number, string',
    hint = 'boolean',
    covers = 'table',
    layout = 'string',
}

local function jsonpaths_from_idx_parts(parts)
    local paths = {}

    for _, part in pairs(parts) do
        if type(part.path) == 'string' then
            table.insert(paths, part.path)
        end
    end

    return paths
end

local function is_multikey_index(parts)
    for _, path in pairs(jsonpaths_from_idx_parts(parts)) do
        if path:find('[*]', 1, true) then
            return true
        end
    end

    return false
end

--
-- check_param_table() template for alter index,
-- includes all index options.
--
local alter_index_template = {
    id = 'number',
    name = 'string',
    type = 'string',
    parts = 'table',
    sequence = 'boolean, number, string, table',
}
for k, v in pairs(index_options) do
    alter_index_template[k] = v
end

--
-- check_param_table() template for create_index(), includes
-- all index options and if_not_exists specifier
--
local create_index_template = table.deepcopy(alter_index_template)
create_index_template.if_not_exists = "boolean"

-- Find a function id by given function name
local function func_id_by_name(func_name, level)
    local func = box.space._func.index.name:get(func_name)
    if func == nil then
        box.error(box.error.NO_SUCH_FUNCTION, func_name, level + 1)
    end
    return func.id
end
box.internal.func_id_by_name = func_id_by_name -- for space.upgrade

-- Normalize array of fields `fields`:
-- - fields referenced as name are resolved to 0-based field number.
-- - fields referenced as 1-based field number are converted to 0-based.
local function normalize_fields(fields, format, what, level)
    -- Do not much care if opts.covers is something strange like
    -- sparse array or map with keys.
    local result = {}
    for i, field in ipairs(fields) do
        local idx
        local field_ref = what .. "[" .. i .. "]: "
        if type(field) == 'string' then
            idx = format_field_index_by_name(format, field)
            if idx == nil then
                box.error(box.error.ILLEGAL_PARAMS, field_ref ..
                          "field was not found by name '" .. field .. "'",
                          level + 1)
            end
        elseif type(field) == 'number' then
            if field <= 0 then
                box.error(box.error.ILLEGAL_PARAMS, field_ref ..
                          "field (number) must be one-based", level + 1)
            end
            idx = field
        else
            box.error(box.error.ILLEGAL_PARAMS, field_ref ..
                      "field (name or number) is expected", level + 1)
        end
        result[i] = idx - 1
    end
    return result
end

box.schema.index.create = atomic_wrapper(function(space_id, name, options)
    check_param(space_id, 'space_id', 'number', 2)
    check_param(name, 'name', 'string', 2)
    check_param_table(options, create_index_template, 2)
    local space = box.space[space_id]
    if not space then
        box.error(box.error.NO_SUCH_SPACE, '#'..tostring(space_id), 2)
    end
    local format = space:format()

    local options_defaults = {
        type = 'tree',
    }
    options = update_param_table(options, options_defaults)
    local type_dependent_defaults = {
        rtree = {parts = { 2, 'array' }, unique = false},
        bitset = {parts = { 2, 'unsigned' }, unique = false},
        other = {parts = { 1, 'unsigned' }, unique = true},
    }
    options_defaults = type_dependent_defaults[options.type]
            or type_dependent_defaults.other
    if not options.parts then
        local fieldno = options_defaults.parts[1]
        if #format >= fieldno then
            local t = format[fieldno].type
            if t ~= 'any' then
                options.parts = {{fieldno, format[fieldno].type}}
            end
        end
    end
    options = update_param_table(options, options_defaults)
    if space.engine == 'vinyl' then
        options_defaults = {
            page_size = box.cfg.vinyl_page_size,
            range_size = box.cfg.vinyl_range_size,
            run_count_per_level = box.cfg.vinyl_run_count_per_level,
            run_size_ratio = box.cfg.vinyl_run_size_ratio,
            bloom_fpr = box.cfg.vinyl_bloom_fpr
        }
    else
        options_defaults = {}
    end
    options = update_param_table(options, options_defaults)
    if options.hint and options.func then
        box.error(box.error.MODIFY_INDEX, name, space.name,
                "functional index can't use hints", 2)
    end

    local _index = box.space[box.schema.INDEX_ID]
    local _vindex = box.space[box.schema.VINDEX_ID]
    if _vindex.index.name:get{space_id, name} then
        if options.if_not_exists then
            return space.index[name], "not created"
        else
            box.error(box.error.INDEX_EXISTS, name, 2)
        end
    end

    local iid = 0
    if options.id then
        iid = options.id
    else
        -- max
        local tuple = _vindex.index[0]
            :select(space_id, { limit = 1, iterator = 'LE' })[1]
        if tuple then
            local id = tuple.id
            if id == space_id then
                iid = tuple.iid + 1
            end
        end
    end
    local parts = update_index_parts(format, options.parts, 2)
    -- create_index() options contains type, parts, etc,
    -- stored separately. Remove these members from index_opts
    local index_opts = {
            dimension = options.dimension,
            unique = options.unique,
            distance = options.distance,
            page_size = options.page_size,
            range_size = options.range_size,
            run_count_per_level = options.run_count_per_level,
            run_size_ratio = options.run_size_ratio,
            bloom_fpr = options.bloom_fpr,
            func = options.func,
            hint = options.hint,
            covers = options.covers,
            layout = options.layout,
    }
    local field_type_aliases = {
        num = 'unsigned'; -- Deprecated since 1.7.2
        uint = 'unsigned';
        str = 'string';
        int = 'integer';
        ['*'] = 'any';
    };
    for _, part in pairs(parts) do
        local field_type = part.type:lower()
        part.type = field_type_aliases[field_type] or field_type
        if field_type == 'num' then
            log.warn("field type '%s' is deprecated since Tarantool 1.7, "..
                     "please use '%s' instead", field_type, part.type)
        end
    end
    -- save parts in old format if possible
    parts = try_simplify_index_parts(parts)
    if options.hint and is_multikey_index(parts) then
        box.error(box.error.MODIFY_INDEX, name, space.name,
                  "multikey index can't use hints", 2)
    end
    if index_opts.func ~= nil and type(index_opts.func) == 'string' then
        index_opts.func = func_id_by_name(index_opts.func, 2)
    end
    if index_opts.covers ~= nil then
        index_opts.covers = normalize_fields(index_opts.covers, format,
                                             'options.covers', 2)
    end
    local sequence_proxy = space_sequence_alter_prepare(format, parts, options,
                                                        space_id, iid,
                                                        space.name, name, 2)
    _index:insert{space_id, iid, name, options.type, index_opts, parts}
    space_sequence_alter_commit(sequence_proxy)
    if index_opts.func ~= nil then
        local _func_index = box.space[box.schema.FUNC_INDEX_ID]
        _func_index:insert{space_id, iid, index_opts.func}
    end

    feedback_save_event('create_index')
    return space.index[name]
end)

box.schema.index.drop = atomic_wrapper(function(space_id, index_id)
    check_param(space_id, 'space_id', 'number', 2)
    check_param(index_id, 'index_id', 'number', 2)
    if index_id == 0 then
        local _space_sequence = box.space[box.schema.SPACE_SEQUENCE_ID]
        -- This is needed to support dropping temporary spaces
        -- in read-only mode, because sequences aren't supported for them yet
        -- and therefore such requests aren't allowed in read-only mode.
        if _space_sequence:get(space_id) ~= nil then
            local sequence_tuple = _space_sequence:delete{space_id}
            if sequence_tuple.is_generated == true then
                -- Delete automatically generated sequence.
                box.schema.sequence.drop(sequence_tuple.sequence_id)
            end
        end
    end
    local _index = box.space[box.schema.INDEX_ID]
    local _func_index = box.space[box.schema.FUNC_INDEX_ID]
    for _, v in box.space._func_index:pairs{space_id, index_id} do
        _func_index:delete({v.space_id, v.index_id})
    end
    _index:delete{space_id, index_id}

    feedback_save_event('drop_index')
end)

box.schema.index.rename = function(space_id, index_id, name)
    utils.box_check_configured(2)
    check_param(space_id, 'space_id', 'number', 2)
    check_param(index_id, 'index_id', 'number', 2)
    check_param(name, 'name', 'string', 2)

    local _index = box.space[box.schema.INDEX_ID]
    call_at(2, _index.update, _index, {space_id, index_id}, {{"=", 3, name}})
end

box.schema.index.alter = atomic_wrapper(function(space_id, index_id, options)
    local space = box.space[space_id]
    if space == nil then
        box.error(box.error.NO_SUCH_SPACE, '#'..tostring(space_id), 2)
    end
    if space.index[index_id] == nil then
        box.error(box.error.NO_SUCH_INDEX_ID, index_id, space.name, 2)
    end
    if options == nil then
        return
    end

    check_param_table(options, alter_index_template, 2)

    if type(space_id) ~= "number" then
        space_id = space.id
    end
    if type(index_id) ~= "number" then
        index_id = space.index[index_id].id
    end
    local format = space:format()
    local _index = box.space[box.schema.INDEX_ID]
    if options.id ~= nil then
        local can_update_field = {id = true, name = true, type = true }
        local can_update = true
        local cant_update_fields = ''
        for k, _ in pairs(options) do
            if not can_update_field[k] then
                can_update = false
                cant_update_fields = cant_update_fields .. ' ' .. k
            end
        end
        if not can_update then
            box.error(box.error.ILLEGAL_PARAMS,
                      "Don't know how to update both id and" ..
                       cant_update_fields, 2)
        end
        local ops = {}
        local function add_op(value, field_no)
            if value then
                table.insert(ops, {'=', field_no, value})
            end
        end
        add_op(options.id, 2)
        add_op(options.name, 3)
        add_op(options.type, 4)
        _index:update({space_id, index_id}, ops)
        return
    end
    local tuple = _index:get{space_id, index_id }
    local parts = {}
    local index_opts = {}
    if type(tuple.opts) == 'number' then
        -- old format
        index_opts.unique = tuple[5] == 1
        local part_count = tuple[6]
        for i = 1, part_count do
            table.insert(parts, {tuple[2 * i + 4], tuple[2 * i + 5]});
        end
    else
        -- new format
        index_opts = tuple.opts
        parts = tuple.parts
    end
    if options.name == nil then
        options.name = tuple.name
    end
    if options.type == nil then
        options.type = tuple.type
    end
    for k, _ in pairs(index_options) do
        if options[k] ~= nil then
            index_opts[k] = options[k]
        end
    end
    if options.hint and options.func then
        box.error(box.error.MODIFY_INDEX, space.index[index_id].name,
                  space.name, "functional index can't use hints", 2)
    end
    if options.parts then
        parts = update_index_parts(format, options.parts, 2)
        -- save parts in old format if possible
        parts = try_simplify_index_parts(parts)
    end
    if options.hint and is_multikey_index(parts) then
        box.error(box.error.MODIFY_INDEX, space.index[index_id].name,
                  space.name, "multikey index can't use hints", 2)
    end
    if options.func ~= nil and type(options.func) == 'string' then
        index_opts.func = func_id_by_name(options.func, 2)
    end
    if options.covers ~= nil then
        index_opts.covers = normalize_fields(options.covers, format,
                                             'options.covers', 2)
    end
    local sequence_proxy = space_sequence_alter_prepare(format, parts, options,
                                                        space_id, index_id,
                                                        space.name,
                                                        options.name, 2)
    _index:replace{space_id, index_id, options.name, options.type,
                   index_opts, parts}
    if index_opts.func ~= nil then
        local _func_index = box.space[box.schema.FUNC_INDEX_ID]
        _func_index:insert{space_id, index_id, index_opts.func}
    end
    space_sequence_alter_commit(sequence_proxy)
end)

-- a static box_tuple_t ** instance for calling box_index_* API
local ptuple = ffi.new('box_tuple_t *[1]')

local function keify(key)
    if key == nil then
        return {}
    elseif type(key) == "table" or is_tuple(key) then
        return key
    end
    return {key}
end

local iterator_t = ffi.typeof('struct iterator')
ffi.metatype(iterator_t, {
    __tostring = function(self)
        return "<iterator state>"
    end;
})

local iterator_gen_luac = function(param, state) -- luacheck: no unused args
    local tuple = internal.iterator_next(state, 2)
    if tuple ~= nil then
        return state, tuple -- new state, value
    else
        return nil
    end
end

local iterator_gen = function(param, state) -- luacheck: no unused args
    if builtin.box_read_ffi_is_disabled then
        return iterator_gen_luac(param, state)
    end
    --[[
        index:pairs() mostly conforms to the Lua for-in loop conventions and
        tries to follow the best practices of Lua community.

        - this generating function is stateless.

        - *param* should contain **immutable** data needed to fully define
          an iterator. *param* is opaque for users. Currently it contains keybuf
          string just to prevent GC from collecting it. In future some other
          variables like space_id, index_id, sc_version will be stored here.

        - *state* should contain **immutable** transient state of an iterator.
          *state* is opaque for users. Currently it contains `struct iterator`
          cdata that is modified during iteration. This is a sad limitation of
          underlying C API. Moreover, the separation of *param* and *state* is
          not properly implemented here. These drawbacks can be fixed in
          future without changing this API.

        Please check out http://www.lua.org/pil/7.3.html for details.
    --]]
    if not ffi.istype(iterator_t, state) then
        box.error(box.error.ILLEGAL_PARAMS, 'Usage: next(param, state)', 2)
    end
    -- next() modifies state in-place
    if builtin.box_iterator_next(state, ptuple) ~= 0 then
        box.error(box.error.last(), 2)
    elseif ptuple[0] ~= nil then
        return state, tuple_bless(ptuple[0]) -- new state, value
    else
        return nil
    end
end

-- global struct port instance to use by select()/get()
local port = ffi.new('struct port')
local port_c = ffi.cast('struct port_c *', port)

-- Helper function to check space:method() usage
local function check_space_arg(space, method, level)
    if type(space) ~= 'table' or (space.id == nil and space.name == nil) then
        local fmt = 'Use space:%s(...) instead of space.%s(...)'
        box.error(box.error.ILLEGAL_PARAMS, string.format(fmt, method, method),
                  level and level + 1)
    end
end
box.internal.check_space_arg = check_space_arg -- for net.box

-- Helper function for nicer error messages
-- in some cases when space object is misused
-- Takes time so should not be used for DML.
local function check_space_exists(space, level)
    local s = box.space[space.id]
    if s == nil then
        box.error(box.error.NO_SUCH_SPACE, space.name, level + 1)
    end
end

-- Helper function to check index:method() usage
local function check_index_arg(index, method, level)
    if type(index) ~= 'table' or (index.id == nil and index.name == nil) then
        local fmt = 'Use index:%s(...) instead of index.%s(...)'
        box.error(box.error.ILLEGAL_PARAMS, string.format(fmt, method, method),
                  level and level + 1)
    end
end
box.internal.check_index_arg = check_index_arg -- for net.box

-- Helper function to check that space have primary key and return it
local function check_primary_index(space, level)
    local pk = space.index[0]
    if pk == nil then
        box.error(box.error.NO_SUCH_INDEX_ID, 0, space.name,
                  level and level + 1)
    end
    return pk
end
box.internal.check_primary_index = check_primary_index -- for net.box

local internal_schema_version_warn_once = false
box.internal.schema_version = function()
    if not internal_schema_version_warn_once then
        internal_schema_version_warn_once = true
        log.warn('box.internal.schema_version will be removed, please use box.info.schema_version instead')
    end
    return box.info.schema_version
end

local function check_iterator_type(opts, key_is_nil, level)
    local opts_type = type(opts)
    if opts ~= nil and opts_type ~= "table" and opts_type ~= "string" and opts_type ~= "number" then
        box.error(box.error.ITERATOR_TYPE, opts, level and level + 1)
    end

    local itype
    if opts_type == "table" and opts.iterator then
        if type(opts.iterator) == "number" then
            itype = opts.iterator
        elseif type(opts.iterator) == "string" then
            itype = box.index[string.upper(opts.iterator)]
            if itype == nil then
                box.error(box.error.ITERATOR_TYPE, opts.iterator,
                          level and level + 1)
            end
        else
            box.error(box.error.ITERATOR_TYPE, tostring(opts.iterator),
                      level and level + 1)
        end
    elseif opts_type == "number" then
        itype = opts
    elseif opts_type == "string" then
        itype = box.index[string.upper(opts)]
        if itype == nil then
            box.error(box.error.ITERATOR_TYPE, opts, level and level + 1)
        end
    else
        -- Use ALL for {} and nil keys and EQ for other keys
        itype = key_is_nil and box.index.ALL or box.index.EQ
    end
    return itype
end

box.internal.check_iterator_type = check_iterator_type

local function check_pairs_opts(opts, key_is_nil, level)
    local iterator = check_iterator_type(opts, key_is_nil, level and level + 1)
    local offset = 0
    local after = nil
    if opts ~= nil and type(opts) == "table" then
        if opts.offset ~= nil then
            offset = opts.offset
        end
        if opts.after ~= nil then
            after = opts.after
            if after ~= nil and type(after) ~= "string" and type(after) ~= "table"
              and not is_tuple(after) then
                box.error(box.error.ITERATOR_POSITION, level and level + 1)
            end
        end
    end
    return iterator, after, offset
end

box.internal.check_pairs_opts = check_pairs_opts

-- pointer to iterator position used by select(), pairs() and tuple_pos()
local iterator_pos = ffi.new('const char *[1]')
local iterator_pos_end = ffi.new('const char *[1]')

--
-- Sets iterator_pos and iterator_pos_end to a user-supplied position.
--
-- The input position may be nil, string, table, or tuple. If the input
-- position is given as string, iterator_pos is set to point to its data,
-- otherwise the iterator_pos data is allocated from the fiber region.
--
-- The ibuf is used to encode a position given as table or tuple.
--
-- Returns true on success. On failure, sets box.error and returns false.
--
local function iterator_pos_set(index, pos, ibuf, level)
    if pos == nil then
        iterator_pos[0] = nil
        iterator_pos_end[0] = nil
        return true
    elseif type(pos) == 'string' then
        iterator_pos[0] = pos
        iterator_pos_end[0] = iterator_pos[0] + #pos
        return true
    else
        ibuf:consume(ibuf.wpos - ibuf.rpos)
        local tuple, tuple_end = tuple_encode(ibuf, pos, level + 1)
        return builtin.box_index_tuple_position(
                index.space_id, index.id, tuple, tuple_end,
                iterator_pos, iterator_pos_end) == 0
    end
end

local base_index_mt = {}
base_index_mt.__index = base_index_mt
--
-- Inherit engine specific index metatables from a base one.
--
local vinyl_index_mt = {}
vinyl_index_mt.__index = vinyl_index_mt
local memtx_index_mt = {}
memtx_index_mt.__index = memtx_index_mt
--
-- When a new method is added below to base index mt, the same
-- method is added both to vinyl and memtx index mt.
--
setmetatable(base_index_mt, {
    __newindex = function(t, k, v)
        vinyl_index_mt[k] = v
        memtx_index_mt[k] = v
        rawset(t, k, v)
    end
})
-- __len and __index
base_index_mt.len = function(index)
    check_index_arg(index, 'len', 2)
    local ret = builtin.box_index_len(index.space_id, index.id)
    if ret == -1 then
        box.error(box.error.last(), 2)
    end
    return tonumber(ret)
end
-- index.bsize
base_index_mt.bsize = function(index)
    check_index_arg(index, 'bsize', 2)
    local ret = builtin.box_index_bsize(index.space_id, index.id)
    if ret == -1 then
        box.error(box.error.last(), 2)
    end
    return tonumber(ret)
end
-- index.quantile
base_index_mt.quantile = function(index, level, begin_key, end_key)
    check_index_arg(index, 'quantile', 2)
    if level == nil then
        box.error(box.error.ILLEGAL_PARAMS,
                  'Usage: index:quantile(level[, begin_key, end_key])', 2)
    end
    if type(level) ~= 'number' then
        box.error(box.error.ILLEGAL_PARAMS, 'level must be a number', 2)
    end
    -- Encode the keys on cord ibuf. Note, since the ibuf may be
    -- reallocated when we encode end_key, we can't use the pointers
    -- returned by tuple_encode(). Instead we remember the begin_key
    -- size and set the pointers after all allocations are done.
    local ibuf = cord_ibuf_take()
    tuple_encode(ibuf, begin_key, 2)
    local begin_key_size = ibuf:size()
    tuple_encode(ibuf, end_key, 2)
    local end_key_size = ibuf:size() - begin_key_size
    begin_key = ibuf.rpos
    end_key = ibuf.rpos + begin_key_size
    -- Call the C API function.
    local quantile_key = ffi.new('const char *[1]')
    local quantile_key_end = ffi.new('const char *[1]')
    local region_svp = builtin.box_region_used()
    local ok = builtin.box_index_quantile(index.space_id, index.id, level,
                                          begin_key, begin_key + begin_key_size,
                                          end_key, end_key + end_key_size,
                                          quantile_key, quantile_key_end) == 0
    cord_ibuf_put(ibuf)
    if not ok then
        box.error(box.error.last(), 2)
    end
    -- Decode the result and clean up the region.
    local result
    if quantile_key[0] ~= nil then
        local ptr
        result, ptr = msgpackffi.decode_unchecked(quantile_key[0])
        assert(ptr == quantile_key_end[0])
    else
        result = nil
    end
    builtin.box_region_truncate(region_svp)
    return result
end
-- index.fselect - formatted select.
-- Options can be passed through opts, fselect_opts and global variables.
-- If an option is in opts table or set in global variable - it must have
-- prefix 'fselect_'. If an option is on fselect_opts table - it may or
-- may not have the prefix.
-- Options:
-- type:
--   'sql' - like mysql result (default)
--   'gh' (or 'github' or 'markdown') - markdown syntax, for pasting to github.
--   'jira' syntax (for pasting to jira)
-- columns: array with desired columns (numbers or names).
-- widths: array with desired widths of columns.
-- max_width: limit entire length of a row string, longest fields will be cut.
--  Set to 0 (default) to detect and use screen width. Set to -1 for no limit.
base_index_mt.fselect = function(index, key, opts, fselect_opts)
    -- Options.
    if type(opts) == 'string' and fselect_opts == nil then
        fselect_opts = {columns = opts}
        opts = nil
    elseif type(fselect_opts) == 'string' then
        fselect_opts = {columns = fselect_opts}
    elseif type(fselect_opts) ~= 'table' then
        fselect_opts = {}
    end

    -- Get global value, like _G[name] but wrapped with pcall for strict mode.
    local function get_global(name)
        local function internal() return _G[name] end
        local success,result = pcall(internal)
        return success and result or nil
    end
    -- Get a value from `opts` table and remove it from the table.
    local function grab_from_opts(name)
        if type(opts) ~= 'table' then return nil end
        local res = opts[name]
        if res ~= nil then opts[name] = nil end
        return res
    end
    -- Find an option in opts, fselect_opts or _G by given name.
    -- In opts and _G the value is searched with 'fselect_' prefix;
    -- In fselect_opts - with or without prefix.
    local function get_opt(name, default, expected_types)
        local expected_types_set = {}
        for _, v in pairs(expected_types:split(',')) do
            expected_types_set[v:strip()] = true
        end
        local prefix_name = 'fselect_' .. name
        local variants = {fselect_opts[prefix_name], fselect_opts[name],
            grab_from_opts(prefix_name), get_global(prefix_name), default }
        local min_i = 0
        local min_v = nil
        for i,v in pairs(variants) do
            -- Can't use ipairs since it's an array with nils.
            -- Have to sort by i, because pairs() doesn't provide order.
            if expected_types_set[type(v)] and (i < min_i or min_v == nil) then
                min_i = i
                min_v = v
            end
        end
        return min_v
    end

    local fselect_type = get_opt('type', 'sql', 'string')
    if fselect_type == 'gh' or fselect_type == 'github' then
        fselect_type = 'markdown'
    end
    if fselect_type ~= 'sql' and fselect_type ~= 'markdown' and fselect_type ~= 'jira' then
        fselect_type = 'sql'
    end
    local columns = get_opt('columns', nil, 'table, string')
    local widths = get_opt('widths', {}, 'table')
    local default_max_width = 0
    if #widths > 0 then default_max_width = -1 end
    local max_width = get_opt('max_width', default_max_width, 'number')
    local min_col_width = 5
    local max_col_width = 1000

    -- Convert comma separated columns into array, to numbers if possible
    if type(columns) == 'string' then
        columns = columns:split(',');
    end
    if columns then
        local res_columns = {}
        for _, str in ipairs(columns) do
            if tonumber(str) then
                table.insert(res_columns, tonumber(str))
            else
                table.insert(res_columns, str:strip())
            end
        end
        columns = res_columns
    end

    -- Screen size autodetection.
    local function detect_width()
        local ffi = require('ffi')
        ffi.cdef('void tnt_rl_get_screen_size(int *rows, int *cols);')
        local colsp = ffi.new('int[1]')
        ffi.C.tnt_rl_get_screen_size(nil, colsp)
        return colsp[0]
    end
    if max_width == 0 then
        max_width = detect_width()
        -- YAML uses several additinal symbols in output, we should shink line.
        local waste_size = 3
        if max_width > waste_size then
            max_width = max_width - waste_size
        else
            max_width = fselect_type == 'sql' and 140 or 260
        end
    end

    -- select and stringify.
    local tab = { }
    local json = require('json')
    for _, t in index:pairs(key, opts) do
        local row = { }
        if columns then
            for _, c in ipairs(columns) do
                table.insert(row, json.encode(t[c]))
            end
        else
            for _, f in t:pairs() do
                table.insert(row, json.encode(f))
            end
        end
        table.insert(tab, row)
    end
    local num_rows = #tab
    local num_cols = 1
    for i = 1, num_rows do
        num_cols = math.max(num_cols, #tab[i])
    end

    -- The JSON encoder above passes through invalid UTF-8 characters untouched.
    -- Replace such strings with the <binary> tag.
    for j = 1,num_cols do
        for i = 1,num_rows do
            if tab[i][j] then
                local _, err = utf8.len(tab[i][j])
                if err then
                    tab[i][j] = '<binary>'
                end
            end
        end
    end

    local fmt = box.space[index.space_id]:format()
    local names = {}
    if columns then
        for _, c in ipairs(columns) do
            if type(c) == 'string' then
                table.insert(names, c)
            elseif fmt[c] then
                table.insert(names, fmt[c].name)
            else
                table.insert(names, 'col' .. tostring(c))
            end
        end
    else
        num_cols = math.max(num_cols, #fmt)
        for c = 1, num_cols do
            table.insert(names, fmt[c] and fmt[c].name or 'col' .. tostring(c))
        end
    end

    local real_width = num_cols + 1 -- including '|' symbols
    for j = 1,num_cols do
        if type(widths[j]) ~= 'number' then
            local width = utf8.len(names[j])
            if fselect_type == 'jira' then
                width = width + 1
            end
            for i = 1,num_rows do
                if tab[i][j] then
                    width = math.max(width, utf8.len(tab[i][j]))
                end
            end
            widths[j] = width
        end
        widths[j] = math.max(widths[j], min_col_width)
        widths[j] = math.min(widths[j], max_col_width)
        real_width = real_width + widths[j]
    end

    -- cut some columns if its width is too big
    while max_width > 0 and real_width > max_width do
        local max_j = 1
        for j = 2,num_cols do
            if widths[j] >= widths[max_j] then max_j = j end
        end
        widths[max_j] = widths[max_j] - 1
        real_width = real_width - 1
    end

    local header_row_delim = fselect_type == 'jira' and '||' or '|'
    local result_row_delim = '|'
    local delim_row_delim = fselect_type == 'sql' and '+' or '|'

    local delim_row = delim_row_delim
    for j = 1,num_cols do
        delim_row = delim_row .. string.rep('-', widths[j]) .. delim_row_delim
    end

    -- format string - cut or fill with spaces to make is exactly n symbols.
    -- also replace spaces with non-break spaces.
    local fmt_str = function(x, n)
        if not x then x = '' end
        local str
        local x_len = utf8.len(x)
        if x_len <= n then
            local add = n - x_len
            local addl = math.floor(add/2)
            local addr = math.ceil(add/2)
            str = string.rep(' ', addl) .. x .. string.rep(' ', addr)
        else
            str = x:sub(1, n)
        end
        return str
    end

    local res = {}

    -- insert into res a string with formatted row.
    local res_insert = function(row, is_header)
        local delim = is_header and header_row_delim or result_row_delim
        local str_row = delim
        local shrink = fselect_type == 'jira' and is_header and 1 or 0
        for j = 1,num_cols do
            str_row = str_row .. fmt_str(row[j], widths[j] - shrink) .. delim
        end
        table.insert(res, str_row)
    end

    -- format result
    if fselect_type == 'sql' then
        table.insert(res, delim_row)
    end
    res_insert(names, true)
    if fselect_type ~= 'jira' then
        table.insert(res, delim_row)
    end
    for i = 1,num_rows do
        res_insert(tab[i], false)
    end
    if fselect_type == 'sql' then
        table.insert(res, delim_row)
    end
    return table.concat(res, '\n')
end
base_index_mt.gselect = function(index, key, opts, fselect_opts)
    if type(fselect_opts) ~= 'table' then fselect_opts = {} end
    fselect_opts['type'] = 'gh'
    return base_index_mt.fselect(index, key, opts, fselect_opts)
end
base_index_mt.jselect = function(index, key, opts, fselect_opts)
    if type(fselect_opts) ~= 'table' then fselect_opts = {} end
    fselect_opts['type'] = 'jira'
    return base_index_mt.fselect(index, key, opts, fselect_opts)
end
-- Lua 5.2 compatibility
base_index_mt.__len = base_index_mt.len
-- min and max
base_index_mt.min_ffi = function(index, key)
    if builtin.box_read_ffi_is_disabled then
        return base_index_mt.min_luac(index, key)
    end
    check_index_arg(index, 'min', 2)
    local ibuf = cord_ibuf_take()
    local pkey, pkey_end = tuple_encode(ibuf, key, 2)
    local nok = builtin.box_index_min(index.space_id, index.id, pkey, pkey_end,
                                      ptuple) ~= 0
    cord_ibuf_put(ibuf)
    if nok then
        box.error(box.error.last(), 2)
    elseif ptuple[0] ~= nil then
        return tuple_bless(ptuple[0])
    else
        return
    end
end
base_index_mt.min_luac = function(index, key)
    check_index_arg(index, 'min', 2)
    key = keify(key)
    return internal.min(index.space_id, index.id, key);
end
base_index_mt.max_ffi = function(index, key)
    if builtin.box_read_ffi_is_disabled then
        return base_index_mt.max_luac(index, key)
    end
    check_index_arg(index, 'max', 2)
    local ibuf = cord_ibuf_take()
    local pkey, pkey_end = tuple_encode(ibuf, key, 2)
    local nok = builtin.box_index_max(index.space_id, index.id, pkey, pkey_end,
                                      ptuple) ~= 0
    cord_ibuf_put(ibuf)
    if nok then
        box.error(box.error.last(), 2)
    elseif ptuple[0] ~= nil then
        return tuple_bless(ptuple[0])
    else
        return
    end
end
base_index_mt.max_luac = function(index, key)
    check_index_arg(index, 'max', 2)
    key = keify(key)
    return internal.max(index.space_id, index.id, key);
end
base_index_mt.random_ffi = function(index, rnd)
    if builtin.box_read_ffi_is_disabled then
        return base_index_mt.random_luac(index, rnd)
    end
    check_index_arg(index, 'random', 2)
    rnd = rnd or math.random()
    if builtin.box_index_random(index.space_id, index.id, rnd,
                                ptuple) ~= 0 then
        box.error(box.error.last(), 2)
    elseif ptuple[0] ~= nil then
        return tuple_bless(ptuple[0])
    else
        return
    end
end
base_index_mt.random_luac = function(index, rnd)
    check_index_arg(index, 'random', 2)
    rnd = rnd or math.random()
    return internal.random(index.space_id, index.id, rnd);
end
-- iteration
base_index_mt.pairs_ffi = function(index, key, opts)
    check_index_arg(index, 'pairs', 2)
    local ibuf = cord_ibuf_take()
    local pkey, pkey_end = tuple_encode(ibuf, key, 2)
    local svp = builtin.box_region_used()
    local itype, after, offset = check_pairs_opts(opts, pkey + 1 >= pkey_end, 2)
    local ok = iterator_pos_set(index, after, ibuf, 2)
    local keybuf = ffi.string(pkey, pkey_end - pkey)
    cord_ibuf_put(ibuf)
    local cdata
    if ok then
        local pkeybuf = ffi.cast('const char *', keybuf)
        cdata = builtin.box_index_iterator_with_offset(
                index.space_id, index.id, itype, pkeybuf, pkeybuf + #keybuf,
                iterator_pos[0], iterator_pos_end[0], offset)
    end
    builtin.box_region_truncate(svp)
    if cdata == nil then
        box.error(box.error.last(), 2)
    end
    return fun.wrap(iterator_gen, keybuf,
        ffi.gc(cdata, builtin.box_iterator_free))
end
base_index_mt.pairs_luac = function(index, key, opts)
    check_index_arg(index, 'pairs', 2)
    key = keify(key)
    local itype, after, offset = check_pairs_opts(opts, #key == 0, 2)
    local keymp = msgpack.encode(key)
    local keybuf = ffi.string(keymp, #keymp)
    local cdata = internal.iterator(index.space_id, index.id, itype, keymp,
        after, offset, 2);
    return fun.wrap(iterator_gen_luac, keybuf,
        ffi.gc(cdata, builtin.box_iterator_free))
end

-- index subtree size
base_index_mt.count_ffi = function(index, key, opts)
    check_index_arg(index, 'count', 2)
    local ibuf = cord_ibuf_take()
    local pkey, pkey_end = tuple_encode(ibuf, key, 2)
    local itype = check_iterator_type(opts, pkey + 1 >= pkey_end, 2);
    local count = builtin.box_index_count(index.space_id, index.id,
        itype, pkey, pkey_end);
    cord_ibuf_put(ibuf)
    if count == -1 then
        box.error(box.error.last(), 2)
    end
    return tonumber(count)
end
base_index_mt.count_luac = function(index, key, opts)
    check_index_arg(index, 'count', 2)
    key = keify(key)
    local itype = check_iterator_type(opts, #key == 0, 2);
    return internal.count(index.space_id, index.id, itype, key);
end

-- 0-based iterator-relative offset of the first matching tuple. If such tuple
-- does not exist, returns the offset at which it would be located if existed.
--
-- For an existing tuple, if index:offset_of(key, {iterator = it}) == N, then
-- index:pairs(nil, {iterator = it, offset = N}) will start the iterator from
-- the same tuple as index:pairs(key, {iterator = it})
base_index_mt.offset_of = function(index, key, opts)
    check_index_arg(index, 'offset_of', 2)
    key = keify(key)
    local itype = check_iterator_type(opts, #key == 0, 2)
    if itype == box.index.EQ then
        itype = box.index.GE
    elseif itype == box.index.REQ then
        itype = box.index.LE
    end
    return index:len() - index:count(key, itype)
end

base_index_mt.get_ffi = function(index, key)
    if builtin.box_read_ffi_is_disabled then
        return base_index_mt.get_luac(index, key)
    end
    check_index_arg(index, 'get', 2)
    local ibuf = cord_ibuf_take()
    local key, key_end = tuple_encode(ibuf, key, 2)
    local nok = builtin.box_index_get(index.space_id, index.id, key, key_end,
                                      ptuple) ~= 0
    cord_ibuf_put(ibuf)
    if nok then
        box.error(box.error.last(), 2)
    elseif ptuple[0] ~= nil then
        return tuple_bless(ptuple[0])
    else
        return
    end
end
base_index_mt.get_luac = function(index, key)
    check_index_arg(index, 'get', 2)
    key = keify(key)
    return internal.get(index.space_id, index.id, key)
end

local function check_select_opts(opts, key_is_nil, level)
    local offset = 0
    local limit = 4294967295
    local iterator = check_iterator_type(opts, key_is_nil,
                                         level and level + 1)
    local after = nil
    local fetch_pos = false
    if opts ~= nil and type(opts) == "table" then
        if opts.offset ~= nil then
            offset = opts.offset
        end
        if opts.limit ~= nil then
            limit = opts.limit
        end
        if opts.after ~= nil then
            after = opts.after
            if type(after) ~= "string" and type(after) ~= "table" and
                    not is_tuple(after) then
                box.error(box.error.ITERATOR_POSITION, level and level + 1)
            end
        end
        if opts.fetch_pos ~= nil then
            fetch_pos = opts.fetch_pos
        end
    end
    return iterator, offset, limit, after, fetch_pos
end

box.internal.check_select_opts = check_select_opts -- for net.box

base_index_mt.select_ffi = function(index, key, opts)
    if builtin.box_read_ffi_is_disabled then
        return base_index_mt.select_luac(index, key, opts)
    end
    check_index_arg(index, 'select', 2)
    local ibuf = cord_ibuf_take()
    local key, key_end = tuple_encode(ibuf, key, 2)
    local key_is_nil = key + 1 >= key_end
    local new_position = nil
    local iterator, offset, limit, after, fetch_pos =
        check_select_opts(opts, key_is_nil, 2)
    local region_svp = builtin.box_region_used()
    local nok = not iterator_pos_set(index, after, ibuf, 2)
    if not nok then
        nok = builtin.box_select_ffi(index.space_id, index.id, key, key_end,
                                     iterator_pos, iterator_pos_end, fetch_pos,
                                     port, iterator, offset, limit) ~= 0
    end
    if not nok and fetch_pos and iterator_pos[0] ~= nil then
        new_position = ffi.string(iterator_pos[0],
                                  iterator_pos_end[0] - iterator_pos[0])
    end
    builtin.box_region_truncate(region_svp)
    cord_ibuf_put(ibuf)
    if nok then
        box.error(box.error.last(), 2)
    end

    local ret = {}
    local entry = port_c.first
    for i=1,tonumber(port_c.size),1 do
        ret[i] = tuple_bless(entry.tuple)
        entry = entry.next
    end
    builtin.port_destroy(port);
    if fetch_pos then
        return ret, new_position
    end
    return ret
end

base_index_mt.select_luac = function(index, key, opts)
    check_index_arg(index, 'select', 2)
    local key = keify(key)
    local key_is_nil = #key == 0
    local iterator, offset, limit, after, fetch_pos =
        check_select_opts(opts, key_is_nil, 2)
    return internal.select(index.space_id, index.id, iterator,
        offset, limit, key, after, fetch_pos)
end

base_index_mt.update = function(index, key, ops)
    check_index_arg(index, 'update', 2)
    return internal.update(index.space_id, index.id, keify(key), ops);
end
base_index_mt.delete = function(index, key)
    check_index_arg(index, 'delete', 2)
    return internal.delete(index.space_id, index.id, keify(key));
end

base_index_mt.stat = function(index)
    return internal.stat(index.space_id, index.id);
end

base_index_mt.compact = function(index)
    return internal.compact(index.space_id, index.id)
end

base_index_mt.drop = function(index)
    check_index_arg(index, 'drop', 2)
    return box.schema.index.drop(index.space_id, index.id)
end
base_index_mt.rename = function(index, name)
    check_index_arg(index, 'rename', 2)
    return box.schema.index.rename(index.space_id, index.id, name)
end
base_index_mt.alter = function(index, options)
    check_index_arg(index, 'alter', 2)
    if index.id == nil or index.space_id == nil then
        box.error(box.error.ILLEGAL_PARAMS, "Usage: index:alter{opts}", 2)
    end
    return box.schema.index.alter(index.space_id, index.id, options)
end
base_index_mt.tuple_pos = function(index, tuple)
    check_index_arg(index, 'tuple_pos', 2)
    local region_svp = builtin.box_region_used()
    local ibuf = cord_ibuf_take()
    local data, data_end = tuple_encode(ibuf, tuple, 2)
    local nok = builtin.box_index_tuple_position(index.space_id, index.id,
                                                 data, data_end, iterator_pos,
                                                 iterator_pos_end) ~= 0
    cord_ibuf_put(ibuf)
    if nok then
        box.error(box.error.last(), 2)
    end
    local ret = ffi.string(iterator_pos[0],
                           iterator_pos_end[0] - iterator_pos[0])
    builtin.box_region_truncate(region_svp)
    return ret
end

local read_ops = {'select', 'get', 'min', 'max', 'count', 'random', 'pairs'}
for _, op in ipairs(read_ops) do
    vinyl_index_mt[op] = base_index_mt[op..'_luac']
    memtx_index_mt[op] = base_index_mt[op..'_ffi']
end
-- Lua 5.2 compatibility
vinyl_index_mt.__pairs = vinyl_index_mt.pairs
vinyl_index_mt.__ipairs = vinyl_index_mt.pairs
memtx_index_mt.__pairs = memtx_index_mt.pairs
memtx_index_mt.__ipairs = memtx_index_mt.pairs

local space_mt = {}
space_mt.len = function(space)
    check_space_arg(space, 'len', 2)
    local pk = space.index[0]
    if pk == nil then
        return 0 -- empty space without indexes, return 0
    end
    return space.index[0]:len()
end
space_mt.count = function(space, key, opts)
    check_space_arg(space, 'count', 2)
    local pk = space.index[0]
    if pk == nil then
        return 0 -- empty space without indexes, return 0
    end
    return pk:count(key, opts)
end
space_mt.offset_of = function(space, key, opts)
    check_space_arg(space, 'offset_of', 2)
    local pk = space.index[0]
    if pk == nil then
        return 0 -- empty space without indexes, return 0
    end
    return pk:offset_of(key, opts)
end
space_mt.bsize = function(space)
    check_space_arg(space, 'bsize', 2)
    local s = builtin.space_by_id(space.id)
    if s == nil then
        box.error(box.error.NO_SUCH_SPACE, space.name, 2)
    end
    return tonumber(builtin.space_bsize(s))
end
space_mt.quantile = function(space, level, begin_key, end_key)
    check_space_arg(space, 'quantile', 2)
    return check_primary_index(space, 2):quantile(level, begin_key, end_key)
end
space_mt.get = function(space, key)
    check_space_arg(space, 'get', 2)
    return check_primary_index(space, 2):get(key)
end
space_mt.select = function(space, key, opts)
    check_space_arg(space, 'select', 2)
    return check_primary_index(space, 2):select(key, opts)
end
space_mt.fselect = function(space, key, opts, fselect_opts)
    check_space_arg(space, 'select', 2)
    return check_primary_index(space, 2):fselect(key, opts, fselect_opts)
end
space_mt.gselect = function(space, key, opts, fselect_opts)
    check_space_arg(space, 'select', 2)
    return check_primary_index(space, 2):gselect(key, opts, fselect_opts)
end
space_mt.jselect = function(space, key, opts, fselect_opts)
    check_space_arg(space, 'select', 2)
    return check_primary_index(space, 2):jselect(key, opts, fselect_opts)
end
space_mt.insert = function(space, tuple)
    check_space_arg(space, 'insert', 2)
    return internal.insert(space.id, tuple);
end
space_mt.replace = function(space, tuple)
    check_space_arg(space, 'replace', 2)
    return internal.replace(space.id, tuple);
end
space_mt.put = space_mt.replace; -- put is an alias for replace
space_mt.update = function(space, key, ops)
    check_space_arg(space, 'update', 2)
    return check_primary_index(space, 2):update(key, ops)
end
space_mt.upsert = function(space, tuple_key, ops, deprecated)
    check_space_arg(space, 'upsert', 2)
    if deprecated ~= nil then
        local msg = "Error: extra argument in upsert call: "
        msg = msg .. tostring(deprecated)
        msg = msg .. ". Usage :upsert(tuple, operations)"
        box.error(box.error.ILLEGAL_PARAMS, msg, 2)
    end
    return internal.upsert(space.id, tuple_key, ops);
end
space_mt.delete = function(space, key)
    check_space_arg(space, 'delete', 2)
    return check_primary_index(space, 2):delete(key)
end
-- Assumes that spaceno has a TREE (NUM) primary key
-- inserts a tuple after getting the next value of the
-- primary key and returns it back to the user
space_mt.auto_increment = function(space, tuple)
    check_space_arg(space, 'auto_increment', 2)
    local pk = check_primary_index(space, 2)
    local max_tuple = call_at(2, pk.max, pk)
    local max = 0
    if max_tuple ~= nil then
        max = max_tuple[1]
    end
    table.insert(tuple, 1, max + 1)
    return space:insert(tuple)
end
space_mt.pairs = function(space, key, opts)
    check_space_arg(space, 'pairs', 2)
    local pk = space.index[0]
    if pk == nil then
        -- empty space without indexes, return empty iterator
        return fun.iter({})
    end
    return pk:pairs(key, opts)
end
space_mt.__pairs = space_mt.pairs -- Lua 5.2 compatibility
space_mt.__ipairs = space_mt.pairs -- Lua 5.2 compatibility
space_mt.truncate = function(space)
    check_space_arg(space, 'truncate', 2)
    return internal.truncate(space.id)
end
space_mt.format = function(space, format)
    check_space_arg(space, 'format', 2)
    return box.schema.space.format(space.id, format)
end
space_mt.upgrade = function(space, ...)
    check_space_arg(space, 'upgrade', 2)
    return box.schema.space.upgrade(space.id, ...)
end
space_mt.drop = function(space)
    check_space_arg(space, 'drop', 2)
    check_space_exists(space, 2)
    return box.schema.space.drop(space.id, space.name)
end
space_mt.rename = function(space, name)
    check_space_arg(space, 'rename', 2)
    check_space_exists(space, 2)
    return box.schema.space.rename(space.id, name)
end
space_mt.alter = function(space, options)
    check_space_arg(space, 'alter', 2)
    check_space_exists(space, 2)
    return box.schema.space.alter(space.id, options)
end
space_mt.create_index = function(space, name, options)
    check_space_arg(space, 'create_index', 2)
    check_space_exists(space, 2)
    return box.schema.index.create(space.id, name, options)
end
space_mt.run_triggers = function(space, yesno)
    check_space_arg(space, 'run_triggers', 2)
    local s = builtin.space_by_id(space.id)
    if s == nil then
        box.error(box.error.NO_SUCH_SPACE, space.name, 2)
    end
    builtin.space_run_triggers(s, yesno)
end
space_mt.insert_arrow = function(space, arrow)
    check_space_arg(space, 'insert_arrow', 2)
    check_space_exists(space, 2)
    return internal.insert_arrow(space.id, arrow);
end
space_mt.frommap = box.internal.space.frommap
space_mt.stat = box.internal.space.stat
space_mt.__index = space_mt

box.schema.index_mt = base_index_mt
box.schema.memtx_index_mt = memtx_index_mt
box.schema.vinyl_index_mt = vinyl_index_mt
box.schema.space_mt = space_mt

--
-- Wrap a global space/index metatable into a space/index local
-- one. Routinely this metatable just indexes the global one. When
-- a user attempts to extend a space or index methods via local
-- space/index metatable instead of from box.schema mt, the local
-- metatable is transformed. Its __index metamethod starts looking
-- up at first in self, and only then into the global mt.
--
local function wrap_schema_object_mt(name)
    local global_mt = box.schema[name]
    local mt = {
        __index = global_mt,
        __ipairs = global_mt.__ipairs,
        __pairs = global_mt.__pairs
    }
    local mt_mt = {}
    mt_mt.__newindex = function(self, k, v)
        mt_mt.__newindex = nil
        mt.__index = function(self, k)
            return mt[k] or box.schema[name][k]
        end
        rawset(mt, k, v)
    end
    setmetatable(mt, mt_mt)
    return mt
end

function box.schema.space.bless(space)
    utils.box_check_configured(2)
    local base_index_mt_name
    if space.engine == 'vinyl' then
        base_index_mt_name = 'vinyl_index_mt'
    else
        base_index_mt_name = 'memtx_index_mt'
    end
    local space_mt = wrap_schema_object_mt('space_mt')

    local func_index_mt_name = base_index_mt_name
    -- Functional index using memtx MVCC must use vinyl
    -- metatable since the MVCC can call the function and
    -- function call is not allowed during FFI call.
    if builtin.memtx_tx_manager_use_mvcc_engine and
       space.engine == 'memtx' then
        func_index_mt_name = 'vinyl_index_mt'
    end

    setmetatable(space, space_mt)
    if type(space.index) == 'table' and space.enabled then
        for j, index in pairs(space.index) do
            local index_mt_name = base_index_mt_name
            if index.func ~= nil then
                index_mt_name = func_index_mt_name
            end
            if type(j) == 'number' then
                setmetatable(index, wrap_schema_object_mt(index_mt_name))
            end
        end
    end
end

local sequence_mt = {}
sequence_mt.__index = sequence_mt

sequence_mt.next = function(self)
    return internal.sequence.next(self.id)
end

sequence_mt.current = function(self)
    local ai64 = ffi.new('int64_t[1]')
    local rc = builtin.box_sequence_current(self.id, ai64)
    if rc < 0 then
        box.error(box.error.last(), 2)
    end
    return ai64[0]
end

sequence_mt.set = function(self, value)
    return internal.sequence.set(self.id, value)
end

sequence_mt.reset = function(self)
    return internal.sequence.reset(self.id)
end

sequence_mt.alter = function(self, opts)
    return box.schema.sequence.alter(self.id, opts)
end

sequence_mt.drop = function(self)
    return box.schema.sequence.drop(self.id)
end

box.sequence = {}
box.schema.sequence = {}

function box.schema.sequence.bless(seq)
    utils.box_check_configured(2)
    setmetatable(seq, {__index = sequence_mt})
end

local sequence_options = {
    step = 'number',
    min = 'number',
    max = 'number',
    start = 'number',
    cache = 'number',
    cycle = 'boolean',
}

local create_sequence_options = table.deepcopy(sequence_options)
create_sequence_options.if_not_exists = 'boolean'

local alter_sequence_options = table.deepcopy(sequence_options)
alter_sequence_options.name = 'string'

box.schema.sequence.create = function(name, opts)
    utils.box_check_configured(2)
    opts = opts or {}
    check_param(name, 'name', 'string', 2)
    check_param_table(opts, create_sequence_options, 2)
    local ascending = not opts.step or opts.step > 0
    local options_defaults = {
        step = 1,
        min = ascending and 1 or INT64_MIN,
        max = ascending and INT64_MAX or -1,
        start = ascending and (opts.min or 1) or (opts.max or -1),
        cache = 0,
        cycle = false,
    }
    opts = update_param_table(opts, options_defaults)
    local id = sequence_resolve(name)
    if id ~= nil then
        if not opts.if_not_exists then
            box.error(box.error.SEQUENCE_EXISTS, name, 2)
        end
        return box.sequence[name], 'not created'
    end
    local _sequence = box.space[box.schema.SEQUENCE_ID]
    call_at(2, _sequence.auto_increment, _sequence,
            {session.euid(), name, opts.step, opts.min, opts.max, opts.start,
             opts.cache, opts.cycle})
    return box.sequence[name]
end

box.schema.sequence.alter = function(name, opts)
    utils.box_check_configured(2)
    check_param_table(opts, alter_sequence_options, 2)
    local id, tuple = sequence_resolve(name)
    if id == nil then
        box.error(box.error.NO_SUCH_SEQUENCE, name, 2)
    end
    if opts == nil then
        return
    end
    local seq = {}
    seq.id, seq.uid, seq.name, seq.step, seq.min, seq.max,
        seq.start, seq.cache, seq.cycle = tuple:unpack()
    opts = update_param_table(opts, seq)
    local _sequence = box.space[box.schema.SEQUENCE_ID]
    call_at(2, _sequence.replace, _sequence,
            {seq.id, seq.uid, opts.name, opts.step, opts.min, opts.max,
             opts.start, opts.cache, opts.cycle})
end

box.schema.sequence.drop = atomic_wrapper(function(name, opts)
    opts = opts or {}
    check_param_table(opts, {if_exists = 'boolean'}, 2)
    local id = sequence_resolve(name)
    if id == nil then
        if not opts.if_exists then
            box.error(box.error.NO_SUCH_SEQUENCE, name, 2)
        end
        return
    end
    revoke_object_privs('sequence', id)
    local _sequence = box.space[box.schema.SEQUENCE_ID]
    local _sequence_data = box.space[box.schema.SEQUENCE_DATA_ID]
    _sequence_data:delete{id}
    _sequence:delete{id}
end)

local function privilege_parse(privs)
    -- TODO: introduce a global privilege -> bit mapping?
    local privs_map = {
        read      = box.priv.R,
        write     = box.priv.W,
        execute   = box.priv.X,
        session   = box.priv.S,
        usage     = box.priv.U,
        create    = box.priv.C,
        drop      = box.priv.D,
        alter     = box.priv.A,
        reference = box.priv.REFERENECE,
        trigger   = box.priv.TRIGGER,
        insert    = box.priv.INSERT,
        update    = box.priv.UPDATE,
        delete    = box.priv.DELETE
    }
    local privs_cp = string.lower(privs):gsub('^[%A]*', '')

    local mask = 0
    -- TODO: prove correctness formally (e.g. via a FSA)?
    repeat
        local matched = false
        -- TODO: replace this with one group pattern when Lua patterns start
        -- supporting disjunction (e.g. '|')
        for priv, bit in pairs(privs_map) do
            privs_cp = string.gsub(privs_cp, '^' .. priv .. '[%A]*',
                                   function()
                                       matched = true
                                       mask = mask + bit
                                       privs_map[priv] = 0
                                       return ''
                                   end)
        end
    until (not matched)

    if privs_cp ~= '' then
        mask = 0
    end

    return mask
end

local function privilege_resolve(privs)
    if type(privs) == 'string' then
        return privilege_parse(privs)
    elseif type(privs) == 'number' then -- TODO: assert type(privs)?
        return privs
    end
    return 0
end

-- allowed combination of privilege bits for object
local priv_object_combo = {
    ["universe"] = box.priv.ALL,
    ["lua_call"] = bit.bor(box.priv.X, box.priv.U),
    ["lua_eval"] = bit.bor(box.priv.X, box.priv.U),
    ["sql"]      = bit.bor(box.priv.X, box.priv.U),
    ["space"]    = bit.bor(box.priv.R, box.priv.W, box.priv.U,
                           box.priv.C, box.priv.D, box.priv.A,
                           box.priv.REFERENCE, box.priv.TRIGGER,
                           box.priv.INSERT, box.priv.UPDATE,
                           box.priv.DELETE),
    ["sequence"] = bit.bor(box.priv.R, box.priv.W, box.priv.U,
                           box.priv.C, box.priv.A, box.priv.D),
    ["function"] = bit.bor(box.priv.X, box.priv.U,
                           box.priv.C, box.priv.D),
    ["role"]     = bit.bor(box.priv.X, box.priv.U,
                           box.priv.C, box.priv.D),
    ["user"]     = bit.bor(box.priv.C, box.priv.A,
                           box.priv.D),
}

local BOX_SPACE_EXECUTE_PRIV_BRIEF = [[
Historically, it was possible to grant the execute privilege on a space although
this action had no effect. The new behavior is to raise an error in this case.

https://tarantool.io/compat/box_space_execute_priv
]]

compat.add_option({
    name = 'box_space_execute_priv',
    default = 'new',
    obsolete = nil,
    brief = BOX_SPACE_EXECUTE_PRIV_BRIEF,
    action = function(is_new)
        if is_new then
            priv_object_combo.space = bit.band(priv_object_combo.space,
                                               bit.bnot(box.priv.X))
        else
            priv_object_combo.space = bit.bor(priv_object_combo.space,
                                              box.priv.X)
        end
    end,
})

--
-- Resolve privilege hex by name and check
-- that bits are allowed for this object type
--
local function privilege_check(privilege, object_type, level)
    local priv_hex = privilege_resolve(privilege)
    if priv_object_combo[object_type] == nil then
        box.error(box.error.UNKNOWN_SCHEMA_OBJECT, object_type, level + 1)
    elseif type(priv_hex) ~= 'number' or priv_hex == 0 or
           bit.band(priv_hex, priv_object_combo[object_type] or 0) ~= priv_hex then
        box.error(box.error.UNSUPPORTED_PRIV, object_type, privilege, level + 1)
    end
    -- Cast to uint64_t to force bit library to use unsigned 64 bit arithmetics.
    -- Otherwise box.priv.ALL == 2^32 - 1 would be treated as signed 32-bit
    -- integer == -1. See https://bitop.luajit.org/semantics.html#range.
    return priv_hex + 0ULL
end

local function privilege_name(privilege)
    local names = {}
    if bit.band(privilege, box.priv.R) ~= 0 then
        table.insert(names, "read")
    end
    if bit.band(privilege, box.priv.W) ~= 0 then
        table.insert(names, "write")
    end
    if bit.band(privilege, box.priv.X) ~= 0 then
        table.insert(names, "execute")
    end
    if bit.band(privilege, box.priv.S) ~= 0 then
        table.insert(names, "session")
    end
    if bit.band(privilege, box.priv.U) ~= 0 then
        table.insert(names, "usage")
    end
    if bit.band(privilege, box.priv.C) ~= 0 then
        table.insert(names, "create")
    end
    if bit.band(privilege, box.priv.D) ~= 0 then
        table.insert(names, "drop")
    end
    if bit.band(privilege, box.priv.A) ~= 0 then
        table.insert(names, "alter")
    end
    if bit.band(privilege, box.priv.REFERENCE) ~= 0 then
        table.insert(names, "reference")
    end
    if bit.band(privilege, box.priv.TRIGGER) ~= 0 then
        table.insert(names, "trigger")
    end
    if bit.band(privilege, box.priv.INSERT) ~= 0 then
        table.insert(names, "insert")
    end
    if bit.band(privilege, box.priv.UPDATE) ~= 0 then
        table.insert(names, "update")
    end
    if bit.band(privilege, box.priv.DELETE) ~= 0 then
        table.insert(names, "delete")
    end
    return table.concat(names, ",")
end

-- Set of object types that have a single global instance.
local singleton_object_types = {
    ['universe'] = true,
    ['lua_eval'] = true,
    ['sql'] = true,
}

local function is_singleton_object_type(object_type)
    return singleton_object_types[object_type]
end

local function object_resolve(object_type, object_name, level)
    if object_name ~= nil and type(object_name) ~= 'string'
            and type(object_name) ~= 'number' then
        box.error(box.error.ILLEGAL_PARAMS, "wrong object name type", level + 1)
    end
    if is_singleton_object_type(object_type) then
        return 0
    end
    if object_type == 'lua_call' then
        return object_name
    end
    if object_type == 'space' then
        if object_name == '' then
            return ''
        end
        local space = box.space[object_name]
        if  space == nil then
            box.error(box.error.NO_SUCH_SPACE, object_name, level + 1)
        end
        return space.id
    end
    if object_type == 'function' then
        if object_name == '' then
            return ''
        end
        local _vfunc = box.space[box.schema.VFUNC_ID]
        local func
        if type(object_name) == 'string' then
            func = _vfunc.index.name:get{object_name}
        else
            func = _vfunc:get{object_name}
        end
        if func then
            return func.id
        else
            box.error(box.error.NO_SUCH_FUNCTION, object_name, level + 1)
        end
    end
    if object_type == 'sequence' then
        if object_name == '' then
            return ''
        end
        local seq = sequence_resolve(object_name)
        if seq == nil then
            box.error(box.error.NO_SUCH_SEQUENCE, object_name, level + 1)
        end
        return seq
    end
    if object_type == 'role' or object_type == 'user' then
        if object_name == '' then
            return ''
        end
        local _vuser = box.space[box.schema.VUSER_ID]
        local role_or_user
        if type(object_name) == 'string' then
            role_or_user = _vuser.index.name:get{object_name}
        else
            role_or_user = _vuser:get{object_name}
        end
        if role_or_user and role_or_user.type == object_type then
            return role_or_user.id
        elseif object_type == 'role' then
            box.error(box.error.NO_SUCH_ROLE, object_name, level + 1)
        else
            box.error(box.error.NO_SUCH_USER, object_name, level + 1)
        end
    end

    box.error(box.error.UNKNOWN_SCHEMA_OBJECT, object_type, level + 1)
end

local function object_name(object_type, object_id, level)
    if is_singleton_object_type(object_type) or object_id == '' then
        return ""
    end
    if object_type == 'lua_call' then
        return object_id
    end
    local space
    if object_type == 'space' then
        space = box.space._vspace
    elseif object_type == 'sequence' then
        space = box.space._sequence
    elseif object_type == 'function' then
        space = box.space._vfunc
    elseif object_type == 'role' or object_type == 'user' then
        space = box.space._vuser
    else
        box.error(box.error.UNKNOWN_SCHEMA_OBJECT, object_type, level + 1)
    end
    return space:get{object_id}.name
end

box.schema.func = {}
box.schema.func.create = function(name, opts)
    utils.box_check_configured(2)
    opts = opts or {}
    check_param_table(opts, { setuid = 'boolean',
                              if_not_exists = 'boolean',
                              language = 'string', body = 'string',
                              is_deterministic = 'boolean',
                              is_sandboxed = 'boolean',
                              is_multikey = 'boolean', aggregate = 'string',
                              takes_raw_args = 'boolean',
                              comment = 'string',
                              param_list = 'table', returns = 'string',
                              exports = 'table', opts = 'table',
                              trigger = 'string, table'}, 2)
    local _func = box.space[box.schema.FUNC_ID]
    local _vfunc = box.space[box.schema.VFUNC_ID]
    local func = _vfunc.index.name:get{name}
    if func then
        if not opts.if_not_exists then
            box.error(box.error.FUNCTION_EXISTS, name, 2)
        end
        return
    end
    -- The field must be an array according to the _func space format
    if type(opts.trigger) == 'string' then
        opts.trigger = {opts.trigger}
    end
    local datetime = os.date("%Y-%m-%d %H:%M:%S")
    opts = update_param_table(opts, { setuid = false, language = 'lua',
                    body = '', routine_type = 'function', returns = 'any',
                    param_list = {}, aggregate = 'none', sql_data_access = 'none',
                    is_deterministic = false, is_sandboxed = false,
                    is_null_call = true, exports = {'LUA'}, opts = setmap{},
                    comment = '', created = datetime, last_altered = datetime,
                    trigger = {}})
    opts.language = string.upper(opts.language)
    opts.setuid = opts.setuid and 1 or 0
    if opts.is_multikey then
        opts.opts.is_multikey = opts.is_multikey
    end
    if opts.takes_raw_args then
        opts.opts.takes_raw_args = opts.takes_raw_args
    end
    call_at(2, _func.auto_increment, _func,
            {session.euid(), name, opts.setuid, opts.language,
             opts.body, opts.routine_type, opts.param_list,
             opts.returns, opts.aggregate, opts.sql_data_access,
             opts.is_deterministic, opts.is_sandboxed,
             opts.is_null_call, opts.exports, opts.opts,
             opts.comment, opts.created, opts.last_altered,
             opts.trigger})
end

box.schema.func.drop = atomic_wrapper(function(name, opts)
    opts = opts or {}
    check_param_table(opts, { if_exists = 'boolean' }, 2)
    local _func = box.space[box.schema.FUNC_ID]
    local _vfunc = box.space[box.schema.VFUNC_ID]
    local fid
    local tuple
    if type(name) == 'string' then
        tuple = _vfunc.index.name:get{name}
    else
        tuple = _vfunc:get{name}
    end
    if tuple then
        fid = tuple.id
    end
    if fid == nil then
        if not opts.if_exists then
            box.error(box.error.NO_SUCH_FUNCTION, name, 2)
        end
        return
    end
    revoke_object_privs('function', fid)
    _func:delete{fid}
end)

function box.schema.func.exists(name_or_id)
    utils.box_check_configured(2)
    local _vfunc = box.space[box.schema.VFUNC_ID]
    local tuple = nil
    if type(name_or_id) == 'string' then
        tuple = _vfunc.index.name:get{name_or_id}
    elseif type(name_or_id) == 'number' then
        tuple = _vfunc:get{name_or_id}
    end
    return tuple ~= nil
end

-- Helper function to check func:method() usage
local function check_func_arg(func, method, level)
    if type(func) ~= 'table' or func.name == nil then
        local fmt = 'Use func:%s(...) instead of func.%s(...)'
        box.error(box.error.ILLEGAL_PARAMS,
                  string.format(fmt, method, method), level + 1)
    end
end

local func_mt = {}

func_mt.drop = function(func, opts)
    check_func_arg(func, 'drop', 2)
    return box.schema.func.drop(func.name, opts)
end

func_mt.call = function(func, args)
    check_func_arg(func, 'call', 2)
    args = args or {}
    if type(args) ~= 'table' then
        box.error(box.error.ILLEGAL_PARAMS, 'Usage: func:call(table)', 2)
    end
    return box.schema.func.call(func.name, unpack(args, 1, table.maxn(args)))
end

function box.schema.func.bless(func)
    utils.box_check_configured(2)
    setmetatable(func, {__index = func_mt})
end

box.schema.func.reload = internal.module_reload
box.schema.func.call = internal.func_call

box.internal.collation = {}
box.internal.collation.create = function(name, coll_type, locale, opts)
    opts = opts or setmap{}
    if type(name) ~= 'string' then
        box.error(box.error.ILLEGAL_PARAMS,
                  "name (first arg) must be a string", 2)
    end
    if type(coll_type) ~= 'string' then
        box.error(box.error.ILLEGAL_PARAMS,
                  "type (second arg) must be a string", 2)
    end
    if type(locale) ~= 'string' then
        box.error(box.error.ILLEGAL_PARAMS,
                  "locale (third arg) must be a string", 2)
    end
    if type(opts) ~= 'table' then
        box.error(box.error.ILLEGAL_PARAMS,
                  "options (fourth arg) must be a table or nil", 2)
    end
    local lua_opts = {if_not_exists = opts.if_not_exists }
    check_param_table(lua_opts, {if_not_exists = 'boolean'}, 2)
    opts.if_not_exists = nil
    local collation_defaults = {
        strength = "tertiary",
    }
    opts = update_param_table(opts, collation_defaults)
    opts = setmap(opts)

    local _coll = box.space[box.schema.COLLATION_ID]
    if lua_opts.if_not_exists then
        local coll = _coll.index.name:get{name}
        if coll then
            return
        end
    end
    call_at(2, _coll.auto_increment, _coll,
            {name, session.euid(), coll_type, locale, opts})
end

box.internal.collation.drop = function(name, opts)
    opts = opts or {}
    check_param_table(opts, { if_exists = 'boolean' }, 2)

    local _coll = box.space[box.schema.COLLATION_ID]
    if opts.if_exists then
        local coll = _coll.index.name:get{name}
        if not coll then
            return
        end
    end
    call_at(2, _coll.index.name.delete, _coll.index.name, {name})
end

box.internal.collation.exists = function(name)
    local _coll = box.space[box.schema.COLLATION_ID]
    local coll = _coll.index.name:get{name}
    return not not coll
end

box.internal.collation.id_by_name = function(name)
    local _coll = box.space[box.schema.COLLATION_ID]
    local coll = _coll.index.name:get{name}
    return coll.id
end

box.schema.user = {}

box.schema.user.password = function(password)
    utils.box_check_configured(2)
    return internal.prepare_auth(box.cfg.auth_type, password)
end

local function prepare_auth_list(password)
    return {
        [box.cfg.auth_type] = internal.prepare_auth(box.cfg.auth_type, password)
    }
end

local function prepare_auth_history(uid)
    if internal.prepare_auth_history ~= nil then
        return internal.prepare_auth_history(uid)
    else
        return {}
    end
end

local function check_password(password, auth_history, level)
    if internal.check_password ~= nil then
        internal.check_password(password, auth_history, level and level + 1)
    end
end

local function chpasswd(uid, new_password, level)
    local _user = box.space[box.schema.USER_ID]
    local auth_history = prepare_auth_history(uid)
    check_password(new_password, auth_history, level and level + 1)
    call_at(level and level + 1, _user.update, _user, {uid},
            {{'=', 5, prepare_auth_list(new_password)},
             {'=', 6, auth_history},
             {'=', 7, math.floor(fiber.time())}})
end

box.schema.user.passwd = function(name, new_password)
    utils.box_check_configured(2)
    if name == nil then
        box.error(box.error.ILLEGAL_PARAMS,
                  "Usage: box.schema.user.passwd([user,] password)", 2)
    end
    if new_password == nil then
        -- change password for current user
        new_password = name
        call_at(2, box.session.su, 'admin', chpasswd, session.uid(),
                new_password)
    else
        -- change password for other user
        local uid = user_resolve(name, 2)
        if uid == nil then
            box.error(box.error.NO_SUCH_USER, name, 2)
        end
        return chpasswd(uid, new_password, 1)
    end
end

box.schema.user.create = atomic_wrapper(function(name, opts)
    utils.box_check_configured(2)
    local uid = user_or_role_resolve(name)
    opts = opts or {}
    local template = {password = 'string', if_not_exists = 'boolean'}
    check_param_table(opts, template, 2)
    if uid then
        if not opts.if_not_exists then
            box.error(box.error.USER_EXISTS, name, 2)
        end
        return
    end
    local auth_list
    if opts.password then
        check_password(opts.password, nil, 2)
        auth_list = prepare_auth_list(opts.password)
    else
        auth_list = setmap({})
    end
    local _user = box.space[box.schema.USER_ID]
    uid = _user:auto_increment{session.euid(), name, 'user', auth_list, {},
                               math.floor(fiber.time())}.id
    -- grant role 'public' to the user
    box.schema.user.grant(uid, 'public')
    -- Grant privilege 'alter' on itself, so that it can
    -- change its password or username.
    box.schema.user.grant(uid, 'alter', 'user', uid)
    -- we have to grant global privileges from setuid function, since
    -- only admin has the ownership over universe and we don't have
    -- grant option
    box.session.su('admin', box.schema.user.grant, uid, 'session,usage', 'universe',
                   nil, {if_not_exists=true})
end)

box.schema.user.exists = function(name)
    utils.box_check_configured(2)
    if user_resolve(name, 2) then
        return true
    else
        return false
    end
end

-- Return expanded origins from the given tuple.
local function origins_from_tuple(tuple)
    if tuple == nil then
        return {[DEFAULT_ORIGIN] = 0}
    end
    if tuple[PRIV_OPTS_FIELD_ID] == nil or
       tuple[PRIV_OPTS_FIELD_ID].origins == nil then
        return {[DEFAULT_ORIGIN] = tuple.privilege}
    end
    return tuple[PRIV_OPTS_FIELD_ID].origins
end

-- Return total privileges from the given origins.
local function privilege_from_origins(origins)
    local new_privilege = 0
    for _, privilege in pairs(origins) do
        new_privilege = bit.bor(new_privilege, privilege)
    end
    return new_privilege
end

-- Return resulting opts from the given origins.
local function opts_from_origins(origins)
    local normalized_origins = {}
    for name, privilege in pairs(origins) do
        if privilege ~= 0 then
            normalized_origins[name] = privilege
        end
    end
    assert(next(normalized_origins) ~= nil)
    -- If only default origin present, we do not need opts.
    if normalized_origins[DEFAULT_ORIGIN] ~= nil and
       next(normalized_origins, next(normalized_origins)) == nil then
        return nil
    end
    return {origins = normalized_origins}
end

local function grant_error(name, object_name, object_type, privilege, level)
    if object_type == 'role' and object_name ~= '' and
       privilege == 'execute' then
        box.error(box.error.ROLE_GRANTED, name, object_name, level + 1)
    end
    local object_repr
    if not is_singleton_object_type(object_type) then
        object_repr = string.format("%s '%s'", object_type, object_name)
    else
        object_repr = object_type
    end
    box.error(box.error.PRIV_GRANTED, name, privilege, object_repr,
              object_type, object_name, level + 1)
end

local function grant(level, uid, name, privilege, object_type,
                     object_name, options)
    -- From user point of view, role is the same thing
    -- as a privilege. Allow syntax grant(user, role).
    if object_name == nil then
        if object_type == nil then
            -- sic: avoid recursion, to not bother with roles
            -- named 'execute'
            object_type = 'role'
            object_name = privilege
            privilege = 'execute'
        else
            -- Allow syntax grant(user, priv, entity)
            -- for entity grants.
            object_name = ''
        end
    end
    local privilege_hex = privilege_check(privilege, object_type, level + 1)

    local oid = object_resolve(object_type, object_name, level + 1)
    options = options or {}
    if options.grantor == nil then
        options.grantor = session.euid()
    else
        options.grantor = user_or_role_resolve(options.grantor)
    end
    if options._origin == nil then
        options._origin = DEFAULT_ORIGIN
    elseif type(options._origin) ~= 'string' then
        box.error(box.error.ILLEGAL_PARAMS, "options parameter '_origin' " ..
                  "should be of type 'string'", level + 1)
    end
    local _priv = box.space[box.schema.PRIV_ID]
    local _vpriv = box.space[box.schema.VPRIV_ID]
    -- add the granted privilege to the current set
    local origins = origins_from_tuple(_vpriv:get({uid, object_type, oid}))

    -- do not execute a replace if it does not change anything
    -- XXX bug if we decide to add a grant option: new grantor
    -- replaces the old one, old grantor is lost
    local old_privilege = origins[options._origin] or 0
    if bit.band(bit.bnot(old_privilege), privilege_hex) ~= 0 then
        -- Update given privileges by origin.
        origins[options._origin] = bit.bor(old_privilege, privilege_hex)
    else
        -- No new privileges can be given.
        if options.if_not_exists then
            return
        end
        grant_error(name, object_name, object_type, privilege, level + 1)
    end

    local new_privilege = privilege_from_origins(origins)
    local opts = opts_from_origins(origins)
    call_at(level + 1, _priv.replace, _priv,
            {options.grantor, uid, object_type, oid, new_privilege,
             opts})
end

local function revoke_error(name, object_name, object_type, privilege, origin,
                            tuple, level)
    local total_privileges = tuple == nil and 0 or tuple.privilege
    local new_privilege = privilege_check(privilege, object_type, level + 1)
    local prev_origin
    local reason
    local code
    if bit.band(new_privilege, total_privileges) == 0 then
        prev_origin = nil
    else
        prev_origin = origin == '' and 'default' or origin
    end

    if object_type == 'role' and object_name ~= '' and
       privilege == 'execute' then
        local msg
        code = box.error.ROLE_NOT_GRANTED
        if prev_origin == nil then
            msg = "User '%s' does not have role '%s'"
        else
            msg = "User '%s' does not have role '%s' provided by %s origin"
        end
        reason = msg:format(name, object_name, prev_origin)
    else
        local msg
        code = box.error.PRIV_NOT_GRANTED
        if prev_origin == nil then
            msg = "User '%s' does not have %s access on %s '%s'"
        else
            msg = "User '%s' does not have %s access on %s '%s' provided by " ..
                  "%s origin"
        end
        reason = msg:format(name, privilege, object_type, object_name,
                            prev_origin)
    end
    box.error({
        code = code,
        reason = reason,
        prev_origin = prev_origin,
    }, level + 1)
end

local function revoke(level, uid, name, privilege, object_type, object_name,
                      options)
    -- From user point of view, role is the same thing
    -- as a privilege. Allow syntax revoke(user, role).
    if object_name == nil then
        if object_type == nil then
            object_type = 'role'
            object_name = privilege
            privilege = 'execute'
        else
            -- Allow syntax revoke(user, privilege, entity)
            -- to revoke entity privileges.
            object_name = ''
        end
    end
    local privilege_hex = privilege_check(privilege, object_type, level + 1)
    options = options or {}
    if options._origin == nil then
        options._origin = DEFAULT_ORIGIN
    elseif type(options._origin) ~= 'string' then
        box.error(box.error.ILLEGAL_PARAMS, "options parameter '_origin' " ..
                  "should be of type 'string'", level + 1)
    end
    local oid = object_resolve(object_type, object_name, level + 1)
    local _priv = box.space[box.schema.PRIV_ID]
    local _vpriv = box.space[box.schema.VPRIV_ID]
    local tuple = _vpriv:get{uid, object_type, oid}
    -- system privileges of admin and guest can't be revoked

    local origins = origins_from_tuple(tuple)
    local old_privilege = origins[options._origin] or 0
    if bit.band(old_privilege, privilege_hex) == 0 then
        -- Privileges cannot be revoked.
        if options.if_exists then
            return
        end
        revoke_error(name, object_name, object_type, privilege, options._origin,
                     tuple, level + 1)
    end
    assert(tuple ~= nil)
    local grantor = tuple.grantor
    -- sic:
    -- a user may revoke more than he/she granted
    -- (erroneous user input)
    --
    origins[options._origin] = bit.band(old_privilege, bit.bnot(privilege_hex))

    local new_privilege = privilege_from_origins(origins)
    if new_privilege == 0 then
        call_at(level + 1, _priv.delete, _priv, {uid, object_type, oid})
    else
        local opts = opts_from_origins(origins)
        call_at(level + 1, _priv.replace, _priv,
                {grantor, uid, object_type, oid, new_privilege, opts})
    end
end

local function drop(uid, level)
    -- recursive delete of user data
    local _vpriv = box.space[box.schema.VPRIV_ID]
    local spaces = box.space[box.schema.VSPACE_ID].index.owner:select{uid}
    for _, tuple in pairs(spaces) do
        box.space[tuple.id]:drop()
    end
    local funcs = box.space[box.schema.VFUNC_ID].index.owner:select{uid}
    for _, tuple in pairs(funcs) do
        box.schema.func.drop(tuple.id)
    end
    -- if this is a role, revoke this role from whoever it was granted to
    local grants = _vpriv.index.object:select{'role', uid}
    for _, tuple in pairs(grants) do
        revoke(level + 1, tuple.grantee, tuple.grantee, uid)
    end
    local sequences = box.space[box.schema.VSEQUENCE_ID].index.owner:select{uid}
    for _, tuple in pairs(sequences) do
        box.schema.sequence.drop(tuple.id)
    end
    -- xxx: hack, we have to revoke session and usage privileges
    -- of a user using a setuid function in absence of create/drop
    -- privileges and grant option
    if box.space._vuser:get{uid}.type == 'user' then
        box.session.su('admin', box.schema.user.revoke, uid,
                       'session,usage', 'universe', nil, {if_exists = true})
    end
    local privs = _vpriv.index.primary:select{uid}

    for _, tuple in pairs(privs) do
        -- we need an additional box.session.su() here, because of
        -- unnecessary check for privilege PRIV_REVOKE in priv_def_check()
        box.session.su("admin", revoke, level + 2, uid, uid, tuple.privilege,
                       tuple.object_type, tuple.object_id)
    end
    box.space[box.schema.USER_ID]:delete{uid}
end

box.schema.user.grant = function(user_name, ...)
    utils.box_check_configured(2)
    local uid = user_resolve(user_name, 2)
    if uid == nil then
        box.error(box.error.NO_SUCH_USER, user_name, 2)
    end
    return grant(1, uid, user_name, ...)
end

box.schema.user.revoke = function(user_name, ...)
    utils.box_check_configured(2)
    local uid = user_resolve(user_name, 2)
    if uid == nil then
        box.error(box.error.NO_SUCH_USER, user_name, 2)
    end
    return revoke(1, uid, user_name, ...)
end

box.schema.user.enable = function(user)
    return box.schema.user.grant(user, "session,usage", "universe", nil,
                                 {if_not_exists = true})
end

box.schema.user.disable = function(user)
    return box.schema.user.revoke(user, "session,usage", "universe", nil,
                                  {if_exists = true})
end

box.schema.user.drop = atomic_wrapper(function(name, opts)
    opts = opts or {}
    check_param_table(opts, { if_exists = 'boolean' }, 2)
    local uid = user_resolve(name, 2)
    if uid ~= nil then
        if uid >= box.schema.SYSTEM_USER_ID_MIN and
           uid <= box.schema.SYSTEM_USER_ID_MAX then
            -- gh-1205: box.schema.user.info fails
            box.error(box.error.DROP_USER, name,
                      "the user or the role is a system", 2)
        end
        if uid == box.session.uid() or uid == box.session.euid() then
            box.error(box.error.DROP_USER, name,
                      "the user is active in the current session", 2)
        end
        return drop(uid, 1)
    end
    if not opts.if_exists then
        box.error(box.error.NO_SUCH_USER, name, 2)
    end
    return
end)

local function info(id, level)
    local _priv = box.space._vpriv
    local privs = {}
    for _, v in pairs(_priv:select{id}) do
        table.insert(
            privs,
            {privilege_name(v.privilege), v.object_type,
             object_name(v.object_type, v.object_id, level + 1)}
        )
    end
    return privs
end

box.schema.user.info = function(user_name)
    utils.box_check_configured(2)
    local uid
    if user_name == nil then
        uid = box.session.euid()
    else
        uid = user_resolve(user_name, 2)
        if uid == nil then
            box.error(box.error.NO_SUCH_USER, user_name, 2)
        end
    end
    return info(uid, 2)
end

box.schema.role = {}

box.schema.role.exists = function(name)
    utils.box_check_configured(2)
    if role_resolve(name) then
        return true
    else
        return false
    end
end

box.schema.role.create = function(name, opts)
    utils.box_check_configured(2)
    opts = opts or {}
    check_param_table(opts, { if_not_exists = 'boolean' }, 2)
    local uid = user_or_role_resolve(name)
    if uid then
        if not opts.if_not_exists then
            box.error(box.error.ROLE_EXISTS, name, 2)
        end
        return
    end
    local _user = box.space[box.schema.USER_ID]
    call_at(2, _user.auto_increment, _user,
            {session.euid(), name, 'role', setmap({}), {},
             math.floor(fiber.time())})
end

box.schema.role.drop = atomic_wrapper(function(name, opts)
    opts = opts or {}
    check_param_table(opts, { if_exists = 'boolean' }, 2)
    local uid = role_resolve(name)
    if uid == nil then
        if not opts.if_exists then
            box.error(box.error.NO_SUCH_ROLE, name, 2)
        end
        return
    end
    if uid >= box.schema.SYSTEM_USER_ID_MIN and
       uid <= box.schema.SYSTEM_USER_ID_MAX or uid == box.schema.SUPER_ROLE_ID then
        -- gh-1205: box.schema.user.info fails
        box.error(box.error.DROP_USER, name,
                  "the user or the role is a system", 2)
    end
    return drop(uid, 1)
end)

local function role_check_grant_revoke_of_sys_priv(level, priv)
    priv = string.lower(priv)
    if (type(priv) == 'string' and (priv:match("session") or priv:match("usage"))) or
        (type(priv) == "number" and (bit.band(priv, 8) ~= 0 or bit.band(priv, 16) ~= 0)) then
        box.error(box.error.GRANT,
                  "system privilege can not be granted to role", level + 1)
    end
end

box.schema.role.grant = function(user_name, ...)
    utils.box_check_configured(2)
    local uid = role_resolve(user_name)
    if uid == nil then
        box.error(box.error.NO_SUCH_ROLE, user_name, 2)
    end
    role_check_grant_revoke_of_sys_priv(2, ...)
    return grant(1, uid, user_name, ...)
end
box.schema.role.revoke = function(user_name, ...)
    utils.box_check_configured(2)
    local uid = role_resolve(user_name)
    if uid == nil then
        box.error(box.error.NO_SUCH_ROLE, user_name, 2)
    end
    role_check_grant_revoke_of_sys_priv(2, ...)
    return revoke(1, uid, user_name, ...)
end
box.schema.role.info = function(role_name)
    utils.box_check_configured(2)
    local rid = role_resolve(role_name)
    if rid == nil then
        box.error(box.error.NO_SUCH_ROLE, role_name, 2)
    end
    return info(rid, 2)
end

--
-- once
--
box.once = function(key, func, ...)
    if type(key) ~= 'string' or type(func) ~= 'function' then
        box.error(box.error.ILLEGAL_PARAMS,
                  "Usage: box.once(key, func, ...)", 2)
    end

    local key = "once"..key
    if box.space._schema:get{key} ~= nil then
        return
    end
    box.ctl.wait_rw()
    box.space._schema:put{key}
    return func(...)
end

--
-- nice output when typing box.space in admin console
--
box.space = {}

local function box_space_mt(tab)
    local t = {}
    for k,v in pairs(tab) do
        -- skip system spaces and views
        if type(k) == 'string' and #k > 0 and k:sub(1,1) ~= '_' then
            t[k] = {
                engine = v.engine,
                is_local = v.is_local,
                temporary = v.temporary,
                is_sync = v.is_sync,
            }
        end
    end
    return t
end

setmetatable(box.space, { __serialize = box_space_mt })

local function check_read_view_arg(rv, method, level)
    if type(rv) ~= 'table' then
        local fmt = 'Use read_view:%s(...) instead of read_view.%s(...)'
        box.error(box.error.ILLEGAL_PARAMS,
                  string.format(fmt, method, method), level + 1)
    end
end

local read_view_methods = {}

--
-- Returns a read view info table:
--  - 'id' - unique read view identifier.
--  - 'name' - read view name.
--  - 'is_system' - true if the read view is used for system purposes.
--  - 'timestamp' - fiber.clock() at the time of read view open.
--  - 'vclock' - box.info.vclock at the time of read view open.
--  - 'signature' - box.info.signature at the time of read view open.
--  - 'status' - 'open' or 'closed'.
--
function read_view_methods:info()
    check_read_view_arg(self, 'info', 2)
    return {
        id = self.id,
        name = self.name,
        is_system = self.is_system,
        timestamp = self.timestamp,
        vclock = self.vclock,
        signature = self.signature,
        status = self.status,
    }
end

--
-- Function stub. Implemented in Tarantool EE.
--
function box.internal.read_view_close(self, level)
    box.error(box.error.READ_VIEW_BUSY, level + 1)
end

--
-- Closes a read view.
--
function read_view_methods:close()
    check_read_view_arg(self, 'close', 2)
    if self.status == 'closed' then
        box.error(box.error.READ_VIEW_CLOSED, 2)
    end
    box.internal.read_view_close(self, 2)
end

local read_view_properties = {
    -- System read views are closed asynchronously so we have to query
    -- the status.
    status = box.internal.read_view_status,
}

local read_view_mt = {
    __index = function(self, key)
        if rawget(self, key) ~= nil then
            return rawget(self, key)
        elseif read_view_properties[key] ~= nil then
            return read_view_properties[key](self)
        elseif read_view_methods[key] ~= nil then
            return read_view_methods[key]
        end
    end,
    __autocomplete = function(self)
        -- Make sure that everything that can be returned by __index is
        -- auto-completed in console. Replace property callbacks with scalars
        -- so that they are auto-completed as data members, not as methods.
        return fun.tomap(fun.chain(fun.map(function(k) return k, true end,
                                           fun.iter(read_view_properties)),
                                   fun.iter(read_view_methods)))
    end,
    __serialize = read_view_methods.info,
}

box.read_view = {}

--
-- Function stub. Implemented in Tarantool EE.
--
function box.read_view.open()
    box.error(box.error.UNSUPPORTED, "Community edition", "read view", 2)
end

--
-- Table of open read views: id -> read view object.
--
-- We use weak ref, because we don't want to pin a read view object after
-- the user drops the last reference to it.
--
local read_view_registry = setmetatable({}, {__mode = 'v'})

--
-- Sets a metatable for a new read view object and adds it to the registry so
-- that it can be returned by box.read_view_list().
--
-- Used in the Tarantool EE source code.
--
function box.internal.read_view_register(rv)
    assert(rv.id ~= nil)
    assert(read_view_registry[rv.id] == nil)
    assert(getmetatable(rv) == nil)
    setmetatable(rv, read_view_mt)
    read_view_registry[rv.id] = rv
    return rv
end

--
-- Returns an array of all open read views sorted by id, ascending.
--
-- Since read view ids grow incrementally and never wrap around,
-- the most recent read view will always be last.
--
function box.read_view.list()
    local list = {}
    for _, rv in ipairs(internal.read_view_list()) do
        local registered_rv = read_view_registry[rv.id]
        if registered_rv == nil then
            -- This is a new read view object that hasn't been used from Lua
            -- yet. Add it to the registry for the next listing to return the
            -- same object.
            registered_rv = box.internal.read_view_register(rv)
        end
        table.insert(list, registered_rv)
    end
    table.sort(list, function(rv1, rv2) return rv1.id < rv2.id end)
    return list
end

box.NULL = msgpack.NULL
box.index.FORWARD_INCLUSIVE = box.index.GE
box.index.FORWARD_EXCLUSIVE = box.index.GT
box.index.REVERSE_INCLUSIVE = box.index.LE
box.index.REVERSE_EXCLUSIVE = box.index.LT
