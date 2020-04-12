#!/usr/bin/env tarantool

local popen = require('popen')
local ffi = require('ffi')
local errno = require('errno')
local fiber = require('fiber')
local clock = require('clock')
local tap = require('tap')

-- For process_is_alive().
ffi.cdef([[
    int
    kill(pid_t pid, int signo);
]])

-- {{{ Helpers

--
-- Verify whether a process is alive.
--
local function process_is_alive(pid)
    local rc = ffi.C.kill(pid, 0)
    return rc == 0 or errno() ~= errno.ESRCH
end

--
-- Verify whether a process is dead or not exist.
--
local function process_is_dead(pid)
    return not process_is_alive(pid)
end

--
-- Yield the current fiber until a condition becomes true or
-- timeout (60 seconds) exceeds.
--
-- Don't use test-run's function to allow to run the test w/o
-- test-run. It is often convenient during debugging.
--
local function wait_cond(func, ...)
    local timeout = 60
    local delay = 0.1

    local deadline = clock.monotonic() + timeout
    local res

    while true do
        res = {func(...)}
        -- Success or timeout.
        if res[1] or clock.monotonic() > deadline then break end
        fiber.sleep(delay)
    end

    return unpack(res, 1, table.maxn(res))
end

-- }}}

--
-- Trivial echo output.
--
local function test_trivial_echo_output(test)
    test:plan(6)

    local script = 'echo -n 1 2 3 4 5'
    local exp_script_output = '1 2 3 4 5'

    -- Start echo, wait it to finish, read the output and close
    -- the handler.
    local ph = popen.shell(script, 'r')
    local pid = ph.pid
    local exp_status = {
        state = popen.state.EXITED,
        exit_code = 0,
    }
    local status = ph:wait()
    test:is_deeply(status, exp_status, 'verify process status')
    local script_output = ph:read()
    test:is(script_output, exp_script_output, 'verify script output')
    local res, err = ph:close()
    test:is_deeply({res, err}, {true, nil}, 'close() successful')

    -- Verify that the process is actually killed.
    local is_dead = wait_cond(process_is_dead, pid)
    test:ok(is_dead, 'the process is killed after close()')

    -- Verify that :close() is idempotent.
    local res, err = ph:close()
    test:is_deeply({res, err}, {true, nil}, 'close() is idempotent')

    -- Sending a signal using a closed handle gives an error.
    local exp_err = 'popen: attempt to operate on a closed handle'
    local res, err = ph:signal(popen.signal.SIGTERM)
    test:is_deeply({res, err}, {nil, exp_err},
                   'signal() on closed handle gives an error')
end

--
-- Test info and force killing of a child process.
--
local function test_kill_child_process(test)
    test:plan(7)

    -- Run and kill a process.
    local script = 'while true; do sleep 10; done'
    local ph = popen.shell(script, 'r')
    local res, err = ph:kill()
    test:is_deeply({res, err}, {true, nil}, 'kill() successful')

    local exp_status = {
        state = popen.state.SIGNALED,
        signo = popen.signal.SIGKILL,
        signame = 'SIGKILL',
    }

    -- Wait for the process termination, verify wait() return
    -- values.
    local status = ph:wait()
    test:is_deeply(status, exp_status, 'wait() return values')

    -- Verify status() return values for a terminated process.
    test:is_deeply(ph.status, exp_status, 'status() return values')

    -- Verify info for a terminated process.
    local info = ph:info()
    test:is(info.pid, nil, 'info.pid is nil')

    local exp_command = ("sh -c '%s'"):format(script)
    test:is(info.command, exp_command, 'verify info.script')

    local exp_opts = {
        stdin = popen.stream.CLOSE,
        stdout = popen.stream.PIPE,
        stderr = popen.stream.PIPE,
        shell = true,
        setsid = true,
        restore_signals = true,
        group_signal = true,
        keep_child = false,
    }
    test:is_deeply(info.opts, exp_opts, 'verify info.opts')

    test:is_deeply(info.status, exp_status, 'verify info.status')

    assert(ph:close())
end

--
-- Test that a loss handle does not leak (at least the
-- corresponding process is killed).
--
local function test_gc(test)
    test:plan(1)

    -- Run a process, verify that it exists.
    local script = 'while true; do sleep 10; done'
    local ph = popen.shell(script, 'r')
    local pid = ph.pid
    assert(process_is_alive(pid))

    -- Loss the handle.
    ph = nil -- luacheck: no unused
    collectgarbage()

    -- Verify that the process is actually killed.
    local is_dead = wait_cond(process_is_dead, pid)
    test:ok(is_dead, 'the process is killed when the handle is collected')
end

--
-- Simple read() / write() test.
--
local function test_read_write(test)
    test:plan(6)

    local payload = 'hello'

    -- The script copies data from stdin to stdout.
    local script = ('prompt=""; read -n %d prompt; echo -n "$prompt"')
        :format(payload:len())
    local ph = popen.shell(script, 'rw')

    -- Write to stdin, read from stdout.
    local res, err = ph:write(payload)
    test:is_deeply({res, err}, {true, nil}, 'write() succeeds')
    local res, err = ph:read()
    test:is_deeply({res, err}, {payload, nil}, 'read() from stdout succeeds')

    assert(ph:close())

    -- The script copies data from stdin to stderr.
    local script = ('prompt=""; read -n %d prompt; echo -n "$prompt" 1>&2')
        :format(payload:len())
    local ph = popen.shell(script, 'rw')

    -- Write to stdin, read from stderr.
    local res, err = ph:write(payload)
    test:is_deeply({res, err}, {true, nil}, 'write() succeeds')
    local res, err = ph:read({stderr = true})
    test:is_deeply({res, err}, {payload, nil}, 'read() from stderr succeeds')

    assert(ph:close())

    -- The same script: copy from stdin to stderr.
    local script = ('prompt=""; read -n %d prompt; echo -n "$prompt" 1>&2')
        :format(payload:len())
    local ph = popen.shell(script, 'rw')

    -- Ensure that read waits for data and does not return
    -- prematurely.
    local res_w, err_w
    fiber.create(function()
        fiber.sleep(0.1)
        res_w, err_w = ph:write(payload)
    end)
    local res, err = ph:read({stderr = true})
    test:is_deeply({res_w, err_w}, {true, nil}, 'write() succeeds')
    test:is_deeply({res, err}, {payload, nil}, 'read() from stderr succeeds')

    assert(ph:close())
end

--
-- Test timeouts: just wait for 0.1 second to elapse, then write
-- data and re-read for sure.
--
local function test_read_timeout(test)
    test:plan(3)

    local payload = 'hello'
    local script = 'prompt=""; read -n 5 prompt && echo -n "$prompt"'
    local ph = popen.shell(script, 'rw')

    -- Read and get a timeout error.
    local exp_err = 'timed out'
    local res, err = ph:read({timeout = 0.1})
    test:is_deeply({res, err.type, tostring(err)}, {nil, 'TimedOut', exp_err},
                   'timeout error')

    -- Write and read after the timeout error.
    local res, err = ph:write(payload)
    test:is_deeply({res, err}, {true, nil}, 'write data')
    local res, err = ph:read()
    test:is_deeply({res, err}, {payload, nil}, 'read data')

    assert(ph:close())
end

--
-- Ensure that read() returns when some data is available (even if
-- it is one byte).
--
local function test_read_chunk(test)
    test:plan(1)

    local payload = 'hello'
    local script = ('echo -n "%s"; sleep 120'):format(payload)
    local ph = popen.shell(script, 'r')

    -- When a first byte is available, read() should return all
    -- bytes arrived at the time.
    local latch = fiber.channel(1)
    local res, err
    fiber.create(function()
        res, err = ph:read()
        latch:put(true)
    end)
    -- Wait 1 second at max.
    latch:get(1)
    test:is_deeply({res, err}, {payload, nil}, 'data available prior to EOF')

    assert(ph:close())
end

local function test_shell_invalid_args(test)
    local function argerr(slot, _)
        if slot == 1 then
            return 'popen.shell: wrong parameter'
        elseif slot == 2 then
            return 'popen.shell: wrong parameter'
        else
            error('Invalid argument check')
        end
    end

    local cases1 = {
        [{ nil }] = argerr(1, 'no value'),
        [{ true }] = argerr(1, 'boolean'),
        [{ false }] = argerr(1, 'boolean'),
        [{ 0 }] = argerr(1, 'number'),
        [{ '' }] = nil, -- string is ok
        [{ { } }] = argerr(1, 'table'),
        [{ popen.shell }] = argerr(1, 'function'),
        [{ io.stdin }] = argerr(1, 'userdata'),
        [{ coroutine.create(function() end) }] = argerr(1, 'thread'),
        [{ require('ffi').new('void *') }] = argerr(1, 'cdata'),
    }

    local cases2 = {
        [{ nil }] = nil, -- nil is ok (rw is optional)
        [{ true }] = argerr(2, 'boolean'),
        [{ false }] = argerr(2, 'boolean'),
        [{ 0 }] = argerr(2, 'number'),
        [{ '' }] = nil, -- string is ok
        [{ { } }] = argerr(2, 'table'),
        [{ popen.shell }] = argerr(2, 'function'),
        [{ io.stdin }] = argerr(2, 'userdata'),
        [{ coroutine.create(function() end) }] = argerr(2, 'thread'),
        [{ require('ffi').new('void *') }] = argerr(2, 'cdata'),
    }

    local plan = 0
    for _, cases in pairs({cases1, cases2}) do
        for _, _ in pairs(cases) do plan = plan + 2 end
    end

    test:plan(plan)

    for args, err in pairs(cases1) do
        local arg = unpack(args)
        local ok, res = pcall(popen.shell, arg)
        test:ok(not ok, ('command (ok): expected string, got %s')
                        :format(type(arg)))
        test:ok(res:match(err), ('command (err): expected string, got %s')
                                :format(type(arg)))
    end

    for args, err in pairs(cases2) do
        local arg = unpack(args)
        local ok, res = pcall(popen.shell, 'echo "test"', arg)
        test:ok(not ok, ('mode (ok): expected string, got %s')
                        :format(type(arg)))
        test:ok(res:match(err), ('mode (err): expected string, got %s')
                                :format(type(arg)))
    end
end

local function test_methods_on_closed_handle(test)
    local methods = {
        signal    = { popen.signal.SIGTERM },
        terminate = { },
        kill      = { },
        wait      = { },
        read      = { },
        write     = { 'popen' },
        info      = { },
        close     = nil -- close call is idempotent one
    }
    local plan = 0
    for _, _ in pairs(methods) do plan = plan + 2 end
    test:plan(plan)

    local ph = popen.shell('echo -n 1 2 3 4 5', 'r')
    ph:close()

    for method, args in pairs(methods) do
        -- TODO: method throws when called on closed handle
        local ok, err = ph[method](ph, unpack(args))
        test:ok(not ok, ('%s (ok) on closed handle'):format(method))
        test:ok(err:match('popen: attempt to operate on a closed handle'),
                ('%s (err) on closed handle'):format(method))
    end
end

local function test_methods_on_invalid_handle(test)
    local methods = {
        signal    = { popen.signal.SIGTERM },
        terminate = nil, -- TODO: test is disabled due to assert
        kill      = nil, -- TODO: test is disabled due to assert
        wait      = { },
        read      = { },
        write     = { 'popen' },
        info      = { },
        close     = { },
    }
    local plan = 0
    for _, _ in pairs(methods) do plan = plan + 4 end
    test:plan(plan)

    local ph = popen.shell('echo -n 1 2 3 4 5', 'r')

    for method, args in pairs(methods) do
        local ok, err = pcall(ph[method])
        test:ok(not ok, ('%s (ok) no handle and args'):format(method))
        -- XXX: kill and terminate dumps signal usage, so method name is omitted
        test:ok(err:match('Bad params, use: ph:'),
                ('%s (err) no handle and args'):format(method))
    end

    local bh = { } -- a table looks like a totally bad handler

    for method, args in pairs(methods) do
        local ok, err = pcall(ph[method], bh, unpack(args))
        test:ok(not ok, ('%s (ok) on invalid handle'):format(method))
        -- XXX: kill and terminate dumps signal usage, so method name is omitted
        test:ok(err:match('Bad params, use: ph:'),
                ('%s (err) on invalid handle'):format(method))
    end
end

local test = tap.test('popen')
test:plan(9)

test:test('trivial_echo_output', test_trivial_echo_output)
test:test('kill_child_process', test_kill_child_process)
test:test('gc', test_gc)
test:test('read_write', test_read_write)
test:test('read_timeout', test_read_timeout)
test:test('read_chunk', test_read_chunk)
test:test('shell_invalid_args', test_shell_invalid_args)
test:test('methods_on_closed_handle', test_methods_on_closed_handle)
test:test('methods_on_invalid_handle', test_methods_on_invalid_handle)

-- Testing plan
--
-- FIXME: Implement this plan.
--
-- - api usage
--   - new
--     - no argv / nil argv
--     - bad argv
--       - wrong type
--       - hole in the table (nil in a middle)
--       - item
--         - wrong type
--       - zero size (w/ / w/o shell)
--     - bad opts
--       - wrong type
--       - {stdin,stdout,stderr}
--         - wrong type
--         - wrong string value
--       - env
--         - wrong type
--         - env item
--           - wrong key type
--           - wrong value type
--           - '=' in key
--           - '\0' in key
--           - '=' in value
--           - '\0' in value
--       - (boolean options)
--         - wrong type
--         - conflicting options (!setsid && signal_group)
--   - shell
--     - bad handle
--     - bad mode
--   - signal
--     - signal
--       - wrong type
--       - unknown value
--   - read
--     - FIXME: more cases
--   - write
--     - FIXME: more cases
--   - __index
--     - zero args (no even handle)
--     - bad handle
--     - FIXME: more cases
--   - __serialize
--     - zero args (no even handle)
--     - bad handle
--   - __gc
--     - zero args (no even handle)
--     - bad handle
--
-- - verify behaviour
--   - popen.new: effect of boolean options
--   - info: verify all four opts.std* actions
--   - info: get both true and false for each opts.<...> boolean
--     option
--
-- - verify dubious code paths
--   - popen.new
--     - env: reallocation of env array
--     - argv construction with and without shell option
--     - std* actions actual behaviour
--   - read / write
--     - write that needs several write() calls
--     - child process die during read / write
--     - FIXME: more cases

os.exit(test:check() and 0 or 1)
