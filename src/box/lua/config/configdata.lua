-- Accumulates configuration data of different kinds and provides
-- accessors.
--
-- Intended to be used as an immutable object.

local fun = require('fun')
local urilib = require('uri')
local uuid = require('uuid')
local instance_config = require('internal.config.instance_config')
local cluster_config = require('internal.config.cluster_config')
local snapshot = require('internal.config.utils.snapshot')

-- {{{ General-purpose utils

-- {'a', 'b', 'c'} => {a = true, b = true, c = true}
local function array2set(t)
    local res = {}
    for _, v in ipairs(t) do
        res[v] = true
    end
    return res
end

-- }}} General-purpose utils

local function choose_iconfig(self, opts)
    if opts ~= nil and opts.instance ~= nil then
        local instances = self._instances
        local instance = instances[opts.instance]
        if instance == nil then
            error(('Unknown instance %q'):format(opts.instance), 0)
        end
        if opts ~= nil and opts.use_default then
            return instance.iconfig_def
        end
        return instance.iconfig
    end

    if opts ~= nil and opts.use_default then
        return self._iconfig_def
    else
        return self._iconfig
    end
end

local methods = {}

-- Acquire a value from the instance config.
--
-- opts:
--     use_default: boolean
--     instance: string
function methods.get(self, path, opts)
    local data = choose_iconfig(self, opts)
    return instance_config:get(data, path)
end

-- Filter data based on the instance schema annotations.
--
-- opts:
--     use_default: boolean
--     instance: string
function methods.filter(self, f, opts)
    local data = choose_iconfig(self, opts)
    return instance_config:filter(data, f)
end

-- List of names of the instances in the same replicaset.
--
-- The names are useful to pass to other methods as opts.peer.
function methods.peers(self)
    return self._peer_names
end

-- Group, replicaset and instance names.
function methods.names(self)
    return {
        group_name = self._group_name,
        replicaset_name = self._replicaset_name,
        instance_name = self._instance_name,
        replicaset_uuid = self._replicaset_uuid,
        instance_uuid = self._instance_uuid,
    }
end

function methods._instance_uri(self, uri_type, opts, log_opts)
    assert(uri_type == 'peer' or uri_type == 'sharding')
    return instance_config:instance_uri(choose_iconfig(self, opts), uri_type,
                                        log_opts)
end

-- Generate a part of a vshard configuration that relates to
-- a particular instance.
--
-- opts:
--     use_default: boolean
--     instance: string
function methods._instance_sharding(self, opts)
    local roles = self:get('sharding.roles', opts)
    if roles == nil or #roles == 0 then
        return nil
    end
    assert(type(roles) == 'table')
    local is_storage = false
    for _, role in pairs(roles) do
        is_storage = is_storage or role == 'storage'
    end
    if not is_storage then
        return nil
    end
    local zone = self:get('sharding.zone', opts)
    local uri = self:_instance_uri('sharding', opts,
                                   {log_prefix = "sharding configuration: "})
    if uri == nil then
        local err = 'No suitable URI provided for instance %q'
        error(err:format(opts.instance), 0)
    end
    --
    -- Currently, vshard does not accept URI without a username. So if we got a
    -- URI without a username, use "guest" as the username without a password.
    --
    local u, err = urilib.parse(uri)
    -- NB: The URI is validated, so the parsing can't fail.
    assert(u ~= nil, err)
    if u.login == nil then
        u.login = 'guest'
        uri = urilib.format(u, true)
    end
    local uuid = self:get('database.instance_uuid', opts)

    local user = self:get({'credentials', 'users', u.login}, opts)
    --
    -- If the user is not described in the credentials, this may mean that the
    -- user already exists and may have all the necessary privileges. If not, an
    -- error will be thrown later.
    --
    if user ~= nil then
        -- Check that the vshard storage user has the credential sharding role.
        local function check_sharding_role(roles)
            if roles == nil or next(roles) == nil then
                return false
            end
            for _, role_name in pairs(roles) do
                if role_name == 'sharding' then
                    return true
                end
            end
            for _, role_name in pairs(roles) do
                local path = {'credentials', 'roles', role_name, 'roles'}
                if check_sharding_role(self:get(path, opts)) then
                    return true
                end
            end
            return false
        end

        if not check_sharding_role(user.roles) then
            local err = "storage user %q should have %q role"
            error(err:format(u.login, 'sharding'), 0)
        end
    end

    return {
        uri = uri,
        uuid = uuid,
        zone = zone,
    }
end

function methods.sharding(self)
    local sharding = {}
    local rebalancers = {}
    for _, group in pairs(self._cconfig.groups) do
        for replicaset_name, value in pairs(group.replicasets) do
            local lock
            local weight
            -- For replicaset-level options, we need to get them from the any
            -- instance of the replicaset.
            local is_rs_options_set = false
            local replicaset_uuid
            local replicaset_cfg = {}
            local is_rebalancer = nil
            for instance_name, _ in pairs(value.instances) do
                local opts = {
                    instance = instance_name,
                    use_default = true,
                }
                if not is_rs_options_set then
                    is_rs_options_set = true
                    lock = self:get('sharding.lock', opts)
                    weight = self:get('sharding.weight', opts)
                end
                if is_rebalancer == nil then
                    local roles = self:get('sharding.roles', opts)
                    if roles ~= nil then -- nil or box.NULL
                        for _, role in pairs(roles) do
                            is_rebalancer = is_rebalancer or
                                role == 'rebalancer'
                        end
                    end
                    if is_rebalancer then
                        table.insert(rebalancers, replicaset_name)
                    end
                end
                local isharding = self:_instance_sharding(opts)
                if isharding ~= nil then
                    if replicaset_uuid == nil then
                        replicaset_uuid = self:get('database.replicaset_uuid',
                            opts)
                    end
                    replicaset_cfg[instance_name] = isharding
                end
            end
            if next(replicaset_cfg) ~= nil then
                sharding[replicaset_name] = {
                    rebalancer = is_rebalancer or nil,
                    replicas = replicaset_cfg,
                    uuid = replicaset_uuid,
                    master = 'auto',
                    lock = lock,
                    weight = weight,
                }
            end
        end
    end
    if #rebalancers > 1 then
        local err = "The rebalancer role must be present in no more than " ..
                    "one replicaset. Replicasets with the role: %s"
        error(err:format(table.concat(rebalancers, ", ")), 0)
    end
    local cfg = {
        sharding = sharding,
        box_cfg_mode = 'manual',
        --
        -- We set this option to "manual" to be able to manage privileges using
        -- the credentials config section and to be able to create the necessary
        -- vshard functions in case all instances in a replicaset are running in
        -- read-only mode (which is possible, for example, in case of
        -- replication.failover == election).
        --
        schema_management_mode = 'manual_access',
        identification_mode = 'name_as_key',
    }

    local vshard_global_options = {
        'shard_index',
        'bucket_count',
        'rebalancer_disbalance_threshold',
        'rebalancer_max_receiving',
        'rebalancer_max_sending',
        'rebalancer_mode',
        'sync_timeout',
        'connection_outdate_delay',
        'failover_ping_timeout',
        'discovery_mode',
        'sched_ref_quota',
        'sched_move_quota',
    }
    for _, v in pairs(vshard_global_options) do
        cfg[v] = instance_config:get(self._iconfig_def, 'sharding.'..v)
    end
    return cfg
end

-- Should be called only if the 'manual' failover method is
-- configured.
function methods.leader(self)
    assert(self._failover == 'manual')
    return self._leader
end

-- Should be called only if the 'manual' failover method is
-- configured.
function methods.is_leader(self)
    assert(self._failover == 'manual')
    return self._leader == self._instance_name
end

function methods.bootstrap_leader(self)
    return self._bootstrap_leader
end

-- Should be called only if the 'supervised' failover method is
-- configured.
function methods.bootstrap_leader_name(self)
    assert(self._failover == 'supervised')
    return self._bootstrap_leader_name
end

-- Calculate an instance configuration for each instance of the
-- given cluster.
local function build_instances(cconfig)
    assert(type(cconfig) == 'table')

    local res = {}

    for group_name, group in pairs(cconfig.groups or {}) do
        for replicaset_name, replicaset in pairs(group.replicasets or {}) do
            for instance_name, _ in pairs(replicaset.instances or {}) do
                assert(res[instance_name] == nil)

                -- Build config for each instance from the cluster
                -- config. Build a config with applied defaults as well.
                local iconfig = cluster_config:instantiate(cconfig,
                    instance_name)
                local iconfig_def = instance_config:apply_default(iconfig)

                -- Substitute variables according to the instance,
                -- replicaset, group names.
                local vars = {
                    instance_name = instance_name,
                    replicaset_name = replicaset_name,
                    group_name = group_name,
                }
                iconfig = instance_config:apply_vars(iconfig, vars)
                iconfig_def = instance_config:apply_vars(iconfig_def, vars)

                res[instance_name] = {
                    replicaset_name = replicaset_name,
                    iconfig = iconfig,
                    iconfig_def = iconfig_def,
                }
            end
        end
    end

    return res
end

-- Filter out peers (instances of our replicaset) from all the
-- instances of the cluster.
local function build_peers(instances, replicaset_name)
    assert(type(instances) == 'table')
    assert(type(replicaset_name) == 'string')

    local res = {}

    for instance_name, def in pairs(instances) do
        assert(res[instance_name] == nil)
        if def.replicaset_name == replicaset_name then
            res[instance_name] = def
        end
    end

    return res
end

local function find_peer_name_by_uuid(peers, instance_uuid)
    for name, peer in pairs(peers) do
        local uuid = instance_config:get(peer.iconfig_def,
                                         'database.instance_uuid')
        if uuid == instance_uuid then
            return name
        end
    end
    return nil
end

function methods.peer_name_by_uuid(self, instance_uuid)
    return find_peer_name_by_uuid(self._peers, instance_uuid)
end

local function find_saved_names(iconfig)
    if type(box.cfg) == 'function' then
        local snap_path = snapshot.get_path(iconfig)
        -- Bootstrap is going to be done, no names are saved.
        if snap_path == nil then
            return nil
        end

        -- Read system spaces of snap file.
        return snapshot.get_names(snap_path)
    end

    -- Box.cfg was already done. No sense in snapshot
    -- reading, we can get all data from memory.
    local peers = {}
    for _, row in ipairs(box.space._cluster:select(nil, {limit = 32})) do
        if row[3] ~= nil then
            peers[row[3]] = row[2]
        end
    end

    return {
        replicaset_name = box.info.replicaset.name,
        replicaset_uuid = box.info.replicaset.uuid,
        instance_name = box.info.name,
        instance_uuid = box.info.uuid,
        peers = peers,
    }
end

-- Return a map, which shows, which instances doesn't have a name
-- set, info about the current replicaset name is also included in map.
function methods.missing_names(self)
    local missing_names = {
        -- Note, that replicaset_name cannot start with underscore (_peers
        -- name is forbidden), so we won't overwrite it with list of peers.
        _peers = {},
    }

    local saved_names = find_saved_names(self._iconfig_def)
    if saved_names == nil then
        -- All names will be set during replicaset bootstrap.
        return missing_names
    end

    -- Missing name of the current replicaset.
    if saved_names.replicaset_name == nil then
        missing_names[self._replicaset_name] = saved_names.replicaset_uuid
    end

    for name, peer in pairs(self._peers) do
        local iconfig = peer.iconfig_def
        -- We allow anonymous replica without instance_uuid. Anonymous replica
        -- cannot have name set, it's enough to validate replicaset_name/uuid.
        if instance_config:get(iconfig, 'replication.anon') then
            goto continue
        end

        -- cfg_uuid may be box.NULL if instance_uuid is not passed to config.
        local cfg_uuid = instance_config:get(iconfig, 'database.instance_uuid')
        if cfg_uuid == box.NULL then
            cfg_uuid = 'unknown'
        end

        if not saved_names.peers[name] then
            missing_names._peers[name] = cfg_uuid
        end

        ::continue::
    end

    return missing_names
end

-- Cluster configuration.
--
-- It is given as is after merging from all the configuration
-- sources. Default values are NOT applied. Variables are NOT
-- substituted.
--
-- Use :get() to receive an instance config for a particular
-- instance with applied defaults and substituted variables.
function methods.cconfig(self)
    return self._cconfig
end

local mt = {
    __index = methods,
}

-- Validate UUIDs and names passed to config against the data,
-- saved inside snapshot. Fail early if mismatch is found.
local function validate_names(saved_names, config_names, iconfig)
    -- Snapshot always has replicaset uuid and
    -- at least one peer in _cluster space.
    if saved_names.replicaset_uuid == nil then
        local snap_path = snapshot.get_path(iconfig)
        error(('Snapshot file %s has no "replicaset_uuid" key in _cluster ' ..
            'system space. The snapshot is likely corrupted.'):format(
            snap_path), 0)
    end
    if saved_names.instance_uuid == uuid.NULL then
        local snap_path = snapshot.get_path(iconfig)
        error(('Snapshot file %s has no "Instance" header with an instance ' ..
            'UUID. The snapshot is likely corrupted.'):format(
            snap_path), 0)
    end
    -- Config always has names set.
    assert(config_names.replicaset_name ~= nil)
    assert(config_names.instance_name ~= nil)

    if config_names.replicaset_uuid ~= nil and
       config_names.replicaset_uuid ~= saved_names.replicaset_uuid then
        error(string.format('Replicaset UUID mismatch. Snapshot: %s, ' ..
                            'config: %s.', saved_names.replicaset_uuid,
                            config_names.replicaset_uuid), 0)
    end

    if saved_names.replicaset_name ~= nil and
       saved_names.replicaset_name ~= config_names.replicaset_name then
        error(string.format('Replicaset name mismatch. Snapshot: %s, ' ..
                            'config: %s.', saved_names.replicaset_name,
                            config_names.replicaset_name), 0)
    end

    if config_names.instance_uuid ~= nil and
       config_names.instance_uuid ~= saved_names.instance_uuid then
        error(string.format('Instance UUID mismatch. Snapshot: %s, ' ..
                            'config: %s.', saved_names.instance_uuid,
                            config_names.instance_uuid), 0)
    end

    if saved_names.instance_name ~= nil and
       saved_names.instance_name ~= config_names.instance_name then
        error(string.format('Instance name mismatch. Snapshot: %s, ' ..
                            'config: %s.', saved_names.instance_name,
                            config_names.instance_name), 0)
    end

    -- Fail early, if current UUID is not set, but no name is found
    -- inside the snapshot file. Ignore this failure, if replica is
    -- configured as anonymous, anon replicas cannot have names.
    if not instance_config:get(iconfig, 'replication.anon') then
        if saved_names.instance_name == nil and
           config_names.instance_uuid == nil then
            error(string.format('Instance name for %s is not set in snapshot' ..
                                ' and UUID is missing in the config. Found ' ..
                                '%s in snapshot.', config_names.instance_name,
                                saved_names.instance_uuid), 0)
        end
        if saved_names.replicaset_name == nil and
           config_names.replicaset_uuid == nil then
            error(string.format('Replicaset name for %s is not set in ' ..
                                'snapshot and  UUID is missing in the ' ..
                                'config. Found %s in snapshot.',
                                config_names.replicaset_name,
                                saved_names.replicaset_uuid), 0)
        end
    end
end

-- A couple of replication.failover specific checks.
local function validate_failover(found, peers, failover, leader)
    if failover ~= 'manual' then
        -- Verify that no leader is set in the "off", "election"
        -- or "supervised" failover mode.
        if leader ~= nil then
            error(('"leader" = %q option is set for replicaset %q of group ' ..
                '%q, but this option cannot be used together with ' ..
                'replication.failover = %q'):format(leader,
                found.replicaset_name, found.group_name, failover), 0)
        end
    end

    if failover ~= 'off' then
        -- Verify that peers in the given replicaset have no direct
        -- database.mode option set if the replicaset is configured
        -- with the "manual", "election" or "supervised" failover
        -- mode.
        --
        -- This check doesn't verify the whole cluster config, only
        -- the given replicaset.
        for peer_name, peer in pairs(peers) do
            local mode = instance_config:get(peer.iconfig, 'database.mode')
            if mode ~= nil then
                error(('database.mode = %q is set for instance %q of ' ..
                    'replicaset %q of group %q, but this option cannot be ' ..
                    'used together with replication.failover = %q'):format(mode,
                    peer_name, found.replicaset_name, found.group_name,
                    failover), 0)
            end
        end
    end

    if failover == 'manual' then
        -- Verify that the 'leader' option is set to a name of an
        -- existing instance from the given replicaset (or unset).
        if leader ~= nil and peers[leader] == nil then
            error(('"leader" = %q option is set for replicaset %q of group ' ..
                '%q, but instance %q is not found in this replicaset'):format(
                leader, found.replicaset_name, found.group_name, leader), 0)
        end
    end

    -- Verify that 'election_mode' is unset or null if
    -- 'failover: supervised'.
    --
    -- The actual box.cfg.election_mode value is deduced from
    -- failover.replicasets.<replicaset_name>.synchro_mode (and
    -- replication.anon).
    --
    -- Also, it is allowed to explicitly set the deduced value.
    if failover == 'supervised' then
        for peer_name, peer in pairs(peers) do
            local election_mode = instance_config:get(peer.iconfig_def,
                'replication.election_mode')
            local is_anon = instance_config:get(peer.iconfig_def,
                'replication.anon')

            -- This option is allowed only in the global scope,
            -- so it can't vary across peers of the same
            -- replicaset, but it is taken on each loop iteration
            -- for simplicity.
            local mode_path = {'failover', 'replicasets', found.replicaset_name,
                'synchro_mode'}
            local synchro_mode = instance_config:get(peer.iconfig_def,
                mode_path)

            -- The election_mode value is deduced automatically,
            -- but if a user set the same value explicitly, it is
            -- OK.
            local expected = 'off'
            if synchro_mode and not is_anon then
                expected = 'manual'
            end

            if election_mode ~= nil and election_mode ~= expected then
                error(('replication.election_mode = %q is set for instance ' ..
                    '%q of replicaset %q of group %q, but this option is ' ..
                    'to be deduced from ' ..
                    'failover.replicasets.%s.synchro_mode when ' ..
                    'replication.failover = "supervised"; the suggestion is ' ..
                    'to leave the replication.election_mode option ' ..
                    'unset'):format(election_mode, peer_name,
                    found.replicaset_name, found.group_name,
                    found.replicaset_name), 0)
            end
        end
    end

    -- Verify that 'election_mode' is 'off' if 'failover: off' or
    -- 'failover: manual'.
    --
    -- The alternative would be silent ignoring the election
    -- mode if failover mode is not 'election'.
    --
    -- For a while, a simple and straightforward approach is
    -- chosen: let the user create an explicit consistent
    -- configuration manually.
    --
    -- We can relax it in a future, though. For example, if two
    -- conflicting options are set in different scopes, we can
    -- ignore one from the outer scope.
    if failover ~= 'election' and failover ~= 'supervised' then
        for peer_name, peer in pairs(peers) do
            local election_mode = instance_config:get(peer.iconfig_def,
                'replication.election_mode')
            if election_mode ~= nil and election_mode ~= 'off' then
                error(('replication.election_mode = %q is set for instance ' ..
                    '%q of replicaset %q of group %q, but this option is ' ..
                    'only applicable if replication.failover = "election"; ' ..
                    'the replicaset is configured with replication.failover ' ..
                    '= %q; if this particular instance requires its own ' ..
                    'election mode, for example, if it is an anonymous ' ..
                    'replica, consider configuring the election mode ' ..
                    'specifically for this particular instance'):format(
                    election_mode, peer_name, found.replicaset_name,
                    found.group_name, failover), 0)
            end
        end
    end
end

-- Validate failover section.
local function validate_failover_config(instances, failover_config)
    if failover_config == nil or failover_config.replicasets == nil then
        return
    end

    local replicasets = {}
    for _, def in pairs(instances) do
        replicasets[def.replicaset_name] = true
    end

    local function verify_instance_in_replicaset(instance_name, replicaset_name)
        if instances[instance_name] == nil then
            error(('instance %s from replicaset %s specified in the '..
                   'failover.replicasets section doesn\'t exist')
                  :format(instance_name, replicaset_name), 0)
        end

        local instance_replicaset = instances[instance_name].replicaset_name
        if instance_replicaset ~= replicaset_name then
            error(('instance %s from replicaset %s is specified in ' ..
                   'the wrong replicaset %s in the failover.replicasets ' ..
                   'configuration section')
                  :format(instance_name, instance_replicaset,
                          replicaset_name), 0)
        end
    end

    for replicaset_name, replicaset in pairs(failover_config.replicasets) do
        if replicasets[replicaset_name] == nil then
            error(('replicaset %s specified in the failover configuration '..
                   'doesn\'t exist'):format(replicaset_name), 0)
        end

        -- Validate the priority section of the specific replicasets.
        for instance_name, _ in pairs(replicaset.priority or {}) do
            verify_instance_in_replicaset(instance_name, replicaset_name)
        end

        -- Validate the learner instances section of the
        -- specific replicaset.
        for _, instance_name in ipairs(replicaset.learners or {}) do
            verify_instance_in_replicaset(instance_name, replicaset_name)
        end
    end
end

-- Verify replication.anon = true prerequisites.
--
-- First, it verifies that the given replicaset contains at least
-- one non-anonymous replica.
--
-- The key idea of the rest of the checks is that an anonymous
-- replica must be in the read-only mode.
--
-- Different failover modes control read-only/read-write mode in
-- different ways, so we need specific checks for each of them in
-- regard of an anonymous replica.
--
-- These checks don't verify the whole cluster config, only the
-- given replicaset.
local function validate_anon(found, peers, failover, leader)
    -- failover: <any>
    --
    -- A replicaset can't consist of only anonymous replicas.
    assert(next(peers) ~= nil)
    local found_non_anon = false
    for _, peer in pairs(peers) do
        local is_anon =
            instance_config:get(peer.iconfig_def, 'replication.anon')
        if not is_anon then
            found_non_anon = true
            break
        end
    end
    if not found_non_anon then
        error(('All the instances of replicaset %q of group %q are ' ..
            'configured as anonymous replicas; it effectively means that ' ..
            'the whole replicaset is read-only; moreover, it means that ' ..
            'default replication.peers construction logic will create ' ..
            'empty upstream list and each instance is de-facto isolated: ' ..
            'neither is connected to any other; this configuration is ' ..
            'forbidden, because it looks like there is no meaningful ' ..
            'use case'):format(found.replicaset_name, found.group_name), 0)
    end

    -- failover: off
    --
    -- An anonymous replica shouldn't be set to RW.
    if failover == 'off' then
        for peer_name, peer in pairs(peers) do
            local is_anon =
                instance_config:get(peer.iconfig_def, 'replication.anon')
            local mode =
                instance_config:get(peer.iconfig_def, 'database.mode')
            if is_anon and mode == 'rw' then
                error(('database.mode = "rw" is set for instance %q of ' ..
                    'replicaset %q of group %q, but this option cannot be ' ..
                    'used together with replication.anon = true'):format(
                    peer_name, found.replicaset_name, found.group_name), 0)
            end
        end
    end

    -- failover: manual
    --
    -- An anonymous replica can't be a leader.
    if failover == 'manual' and leader ~= nil then
        assert(peers[leader] ~= nil)
        local iconfig_def = peers[leader].iconfig_def
        local is_anon = instance_config:get(iconfig_def, 'replication.anon')
        if is_anon then
            error(('replication.anon = true is set for instance %q of ' ..
                'replicaset %q of group %q that is configured as a ' ..
                'leader; a leader can not be an anonymous replica'):format(
                leader, found.replicaset_name, found.group_name), 0)
        end
    end

    -- failover: election
    --
    -- An anonymous replica can be in `election_mode: off`, but
    -- not any other.
    --
    -- Let's look on illustrative examples below. The following
    -- one works.
    --
    -- replicasets:
    --   r-001:
    --     replication:
    --       failover: election
    --     instances:
    --       i-001: {}       # candidate
    --       i-002: {}       # candidate
    --       i-003: {}       # candidate
    --       i-004:          # off --------+
    --         replication:  #             +--> OK
    --           anon: true  # anonymous --+
    --
    -- All the non-anonymous instances have effective default
    -- 'replication.election_mode: candidate', while anonymous
    -- replicas default to 'off'.
    --
    -- However, the following example doesn't work.
    --
    -- replicasets:
    --   r-001:
    --     replication:
    --       failover: election
    --       election_mode: candidate # !!
    --     instances:
    --       i-001: {}       # candidate
    --       i-002: {}       # candidate
    --       i-003: {}       # candidate
    --       i-004:          # candidate --+
    --         replication:  #             +--> error
    --           anon: true  # anonymous --+
    --
    -- The default 'off' is not applied, because the explicit
    -- 'candidate' value is set in the replicaset scope. It can be
    -- fixed like so:
    --
    -- <...>
    --       i-004:
    --         replication:
    --           anon: true
    --           election_mode: off # !!
    if failover == 'election' then
        for peer_name, peer in pairs(peers) do
            local is_anon = instance_config:get(peer.iconfig_def,
                'replication.anon')
            local election_mode = instance_config:get(peer.iconfig_def,
                'replication.election_mode')
            if is_anon and election_mode ~= nil and election_mode ~= 'off' then
                error(('replication.election_mode = %q is set for instance ' ..
                    '%q of replicaset %q of group %q, but this option ' ..
                    'cannot be used together with replication.anon = true; ' ..
                    'consider setting replication.election_mode = "off" ' ..
                    'explicitly for this instance'):format(
                    election_mode, peer_name, found.replicaset_name,
                    found.group_name), 0)
            end
        end
    end
end

local function validate_misplacing(cconfig)
    for group_name, group_cfg in pairs(cconfig.groups) do
        if group_cfg.replicasets == nil or
                next(group_cfg.replicasets) == nil then
            error(('group %q should include at ' ..
                   'least one replicaset.'):format(group_name), 0)
        end

        for replicaset_name, replicaset_cfg in pairs(group_cfg.replicasets) do
            if replicaset_cfg.instances == nil or
                    next(replicaset_cfg.instances) == nil then
                error(('replicaset %q should include at ' ..
                       'least one instance.'):format(replicaset_name), 0)
            end
        end
    end
end

-- Check startup conditions.
local function validate_startup(instance_name, iconfig_def)
    local is_startup = type(box.cfg) == 'function'
    if not is_startup then
        return
    end

    local no_snap = snapshot.get_path(iconfig_def) == nil
    local isolated = instance_config:get(iconfig_def, 'isolated')

    -- Forbid startup without a local snapshot in the isolated
    -- mode.
    if no_snap and isolated then
        error(('Startup failure.\nThe isolated mode is enabled and the ' ..
            'instance %q has no local snapshot. An attempt to bootstrap ' ..
            'the instance would lead to the split-brain situation.'):format(
            instance_name), 0)
    end

    -- TODO: There is a situation, which looks similar, but we
    -- don't report an error in the case. It is a startup without
    -- a local snapshot with replication.peers configured as an
    -- empty list if there are other instances in the replicaset.
    -- Are there cases, when it is OK? Maybe if the instance is
    -- assigned as a bootstrap leader? Now we pass it over, but
    -- maybe it worth to revisit it later and report an error in
    -- some definitely/likely erroreous cases.
end

-- Perform checks related to the multi-master setup.
local function validate_multi_master(iconfig_def, peers)
    -- Several instances can be configured as RW simultaneously in
    -- the replication.failover = off mode. Nothing to verify
    -- otherwise.
    local failover = instance_config:get(iconfig_def, 'replication.failover')
    if failover ~= 'off' then
        return
    end

    -- Count RW instances.
    local rw_count = 0
    for _, peer in pairs(peers) do
        local mode = instance_config:get(peer.iconfig_def, 'database.mode')
        if mode == 'rw' then
            rw_count = rw_count + 1
        end
    end

    -- Zero or one RW instance -- nothing to verify.
    if rw_count < 2 then
        return
    end

    -- Verify that the autoexpelling is disabled.
    if instance_config:get(iconfig_def, 'replication.autoexpel.enabled') then
        error('replication.autoexpel.enabled = true doesn\'t support the ' ..
            'multi-master configuration', 0)
    end
end

local function validate_replicaset_names_are_unique(cconfig)
    local replicaset2group = {}

    for group_name, group in pairs(cconfig.groups) do
        for replicaset_name, _ in pairs(group.replicasets) do
            local dup_group_name = replicaset2group[replicaset_name]

            -- Currently, it's not possible to handle
            -- groups, replicasets, instances with the same
            -- names in the same subgroup. E.g. such cluster
            -- config are considered ok (gh-10917):
            -- * g-001
            --   * r-001
            --   * r-001 (duplicate)

            -- Duplicating replicaset name is found within
            -- distinct groups.
            if dup_group_name ~= nil then
                assert(group_name ~= dup_group_name)

                error(('found replicasets with the same name %q in the ' ..
                       'groups %q and %q.')
                      :format(replicaset_name, dup_group_name, group_name), 0)
            end

            replicaset2group[replicaset_name] = group_name
        end
    end
end

local function validate_instance_names_are_unique(cconfig)
    local instance2group = {}
    local instance2replicaset = {}

    for group_name, group in pairs(cconfig.groups) do
        for replicaset_name, replicaset in pairs(group.replicasets) do
            for instance_name, _ in pairs(replicaset.instances) do
                local dup_group_name = instance2group[instance_name]
                local dup_replicaset_name =
                    instance2replicaset[instance_name]

                -- Currently, it's not possible to handle
                -- groups, replicasets, instances with the same
                -- names in the same subgroup. E.g. such cluster
                -- config are considered ok (gh-10917):
                -- * g-001
                --   * r-001
                --     * i-001
                --     * i-001 (duplicate)

                -- Duplicating instance name is found within
                -- distinct replicasets.
                if group_name == dup_group_name then
                    assert(replicaset_name ~= dup_replicaset_name)

                    error(('found instances with the same name %q in ' ..
                           'the replicasets %q and %q in the group %q.')
                          :format(instance_name, dup_replicaset_name,
                                  replicaset_name, group_name), 0)
                end

                -- Duplicating instance name is found within
                -- distinct groups.
                if dup_group_name ~= nil then
                    assert(group_name ~= dup_group_name)
                    assert(replicaset_name ~= dup_replicaset_name)

                    error(('found instances with the same name %q in ' ..
                           'the replicaset %q in the group %q and in the ' ..
                           'replicaset %q in the group %q.')
                           :format(instance_name, dup_replicaset_name,
                                   dup_group_name, replicaset_name,
                                   group_name), 0)
                end

                assert(dup_replicaset_name == nil)

                instance2group[instance_name] = group_name
                instance2replicaset[instance_name] = replicaset_name
            end
        end
    end
end

local function new(iconfig, cconfig, instance_name)
    -- Find myself in a cluster config, determine peers in the same
    -- replicaset.
    local found = cluster_config:find_instance(cconfig, instance_name)
    assert(found ~= nil)

    validate_misplacing(cconfig)

    validate_replicaset_names_are_unique(cconfig)
    validate_instance_names_are_unique(cconfig)

    -- Precalculate configuration with applied defaults.
    local iconfig_def = instance_config:apply_default(iconfig)

    -- Substitute {{ instance_name }} with actual instance name in
    -- the original config and in the config with defaults.
    --
    -- The same for {{ replicaset_name }} and {{ group_name }}.
    local vars = {
        instance_name = instance_name,
        replicaset_name = found.replicaset_name,
        group_name = found.group_name,
    }
    iconfig = instance_config:apply_vars(iconfig, vars)
    iconfig_def = instance_config:apply_vars(iconfig_def, vars)

    local replicaset_uuid = instance_config:get(iconfig_def,
        'database.replicaset_uuid')
    local instance_uuid = instance_config:get(iconfig_def,
        'database.instance_uuid')

    -- Save instance configs for all instances of the cluster and
    -- save instance from our replicaset separately.
    local instances = build_instances(cconfig)
    local peers = build_peers(instances, found.replicaset_name)

    -- Make the order of the peers predictable and the same on all
    -- instances in the replicaset.
    local peer_names = fun.iter(peers):totable()
    table.sort(peer_names)

    -- The replication.failover option is forbidden for the
    -- instance scope of the cluster config, so it is common for
    -- the whole replicaset. We can extract it from the
    -- configuration of the given instance.
    --
    -- There is a nuance: the option still can be set using an
    -- environment variable. We can't detect incorrect usage in
    -- this case (say, different failover modes for different
    -- instances in the same replicaset), because we have no
    -- access to environment of other instances.
    local failover = instance_config:get(iconfig_def, 'replication.failover')
    local leader = found.replicaset.leader
    validate_failover(found, peers, failover, leader)

    local failover_config = instance_config:get(iconfig_def, 'failover')
    validate_failover_config(instances, failover_config)

    local bootstrap_strategy = instance_config:get(iconfig_def,
        'replication.bootstrap_strategy')
    local bootstrap_leader = found.replicaset.bootstrap_leader
    if bootstrap_strategy ~= 'config' then
        if bootstrap_leader ~= nil then
            error(('The "bootstrap_leader" option cannot be set for '..
                   'replicaset %q because "bootstrap_strategy" for instance '..
                   '%q is not "config"'):format(found.replicaset_name,
                                                instance_name), 0)
        end
    elseif bootstrap_leader == nil then
        error(('The "bootstrap_leader" option cannot be empty for replicaset '..
               '%q because "bootstrap_strategy" for instance %q is '..
               '"config"'):format(found.replicaset_name, instance_name), 0)
    else
        if peers[bootstrap_leader] == nil then
            error(('"bootstrap_leader" = %q option is set for replicaset %q '..
                   'of group %q, but instance %q is not found in this '..
                   'replicaset'):format(bootstrap_leader, found.replicaset_name,
                                        found.group_name, bootstrap_leader), 0)
        end
    end

    -- Verify that there is at least one non-anonymous replica in
    -- the given replicaset.
    --
    -- Verify that `replication.anon: true` (if any) doesn't
    -- conflict with any other option (say, database.mode,
    -- <replicaset>.leader or replication.election_mode).
    validate_anon(found, peers, failover, leader)


    -- Verify "replication.failover" = "supervised" strategy
    -- prerequisites.
    local bootstrap_leader_name
    if failover == 'supervised' then
        -- In the 'auto' bootstrap strategy an instance goes to RW
        -- on its own to bootstrap the replicaset.
        --
        -- In the 'supervised' and 'native' strategies an instance
        -- waits for the coordinator's command to start
        -- bootstrapping ('guest' use should have a permission to
        -- call the 'failover.execute' function).
        --
        -- Other strategies were not verified with the supervised
        -- failover, so report an explicit error about them.
        local supported = {
            auto = true,
            supervised = true,
            native = true,
        }
        if not supported[bootstrap_strategy] then
            error(('"bootstrap_strategy" = %q is set for replicaset %q, but ' ..
                'it is not supported with "replication.failover" = ' ..
                '"supervised"'):format(bootstrap_strategy,
                found.replicaset_name), 0)
        end
        assert(bootstrap_leader == nil)

        local failover_replicaset = instance_config:get(iconfig_def,
            {'failover', 'replicasets', found.replicaset_name}) or {}

        local failover_learners = array2set(failover_replicaset.learners or {})
        local failover_priorities = failover_replicaset.priority or {}

        -- Choose the first non-anonymous non-learner instance
        -- with the highest priority specified in the failover
        -- configuration section.
        local max_priority = -math.huge
        for _, peer_name in ipairs(peer_names) do
            assert(peers[peer_name] ~= nil)
            local iconfig_def = peers[peer_name].iconfig_def
            local is_anon = instance_config:get(iconfig_def, 'replication.anon')
            local is_learner = failover_learners[peer_name]
            local priority = failover_priorities[peer_name] or 0

            if not is_anon and not is_learner and priority > max_priority then
                bootstrap_leader_name = peer_name
                max_priority = priority
            end
        end
    end

    -- Names and UUIDs are always validated: during instance start
    -- and during config reload.
    local saved_names = find_saved_names(iconfig_def)
    if saved_names ~= nil then
        validate_names(saved_names, {
            replicaset_name = found.replicaset_name,
            instance_name = instance_name,
            -- UUIDs from config, generated one should not be used here.
            replicaset_uuid = replicaset_uuid,
            instance_uuid = instance_uuid,
        }, iconfig_def)
    end

    -- A couple of checks that are only performed on startup.
    validate_startup(instance_name, iconfig_def)

    -- Checks that are related to the multi-master setup.
    -- Some functionality doesn't support it.
    validate_multi_master(iconfig_def, peers)

    return setmetatable({
        _iconfig = iconfig,
        _iconfig_def = iconfig_def,
        _cconfig = cconfig,
        _peer_names = peer_names,
        _replicaset_uuid = replicaset_uuid,
        _instance_uuid = instance_uuid,
        _instances = instances,
        _peers = peers,
        _group_name = found.group_name,
        _replicaset_name = found.replicaset_name,
        _instance_name = instance_name,
        _failover = failover,
        _leader = leader,
        _bootstrap_leader = bootstrap_leader,
        _bootstrap_leader_name = bootstrap_leader_name,
    }, mt)
end

return {
    new = new,
}
