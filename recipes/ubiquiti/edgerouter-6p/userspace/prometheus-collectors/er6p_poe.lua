-- er6p_poe.lua — Prometheus collector for EdgeRouter 6P passive PoE
-- Reads ISL28022 hwmon (voltage/current/power) and per-port sysfs status
-- Deploy to: /usr/lib/lua/prometheus-collectors/er6p_poe.lua
-- Depends: prometheus-node-exporter-lua, er6p-poe kernel module, isl28022

local METRIC_NAMESPACE = "er6p_poe"

local PORTS = { "eth1", "eth3", "eth4" }

local MODES = { "off", "24v", "48v" }

local function rtrim(s)
    return (string.gsub(s, "\n$", ""))
end

local function scrape()
    -- Bus-level metrics from ISL28022 hwmon
    local fd = io.popen("ls -1d /sys/bus/i2c/devices/1-0040/hwmon/hwmon* 2>/dev/null")
    if fd then
        for line in fd:lines() do
            local voltage_mv = get_contents(line .. "/in0_input")
            local current_ma = get_contents(line .. "/curr1_input")
            local power_uw = get_contents(line .. "/power1_input")

            if voltage_mv ~= "" then
                metric(METRIC_NAMESPACE .. "_bus_voltage_volts", "gauge", nil,
                    tonumber(rtrim(voltage_mv)) / 1000)
            end
            if current_ma ~= "" then
                metric(METRIC_NAMESPACE .. "_bus_current_amps", "gauge", nil,
                    tonumber(rtrim(current_ma)) / 1000)
            end
            if power_uw ~= "" then
                metric(METRIC_NAMESPACE .. "_bus_power_watts", "gauge", nil,
                    tonumber(rtrim(power_uw)) / 1000000)
            end
        end
        fd:close()
    end

    -- Per-port enable and mode from sysfs
    local port_enable_metric = metric(METRIC_NAMESPACE .. "_port_enabled", "gauge")
    local port_mode_metric = metric(METRIC_NAMESPACE .. "_port_mode", "gauge")

    for _, port in ipairs(PORTS) do
        local base = "/sys/kernel/er6p_poe/" .. port .. "/"
        local enable = get_contents(base .. "enable")
        local mode = get_contents(base .. "mode")

        if enable ~= "" then
            port_enable_metric({ port = port }, tonumber(rtrim(enable)) or 0)
        end

        if mode ~= "" then
            mode = rtrim(mode)
            for _, m in ipairs(MODES) do
                port_mode_metric({ port = port, mode = m },
                    (mode == m and 1 or 0))
            end
        end
    end
end

return { scrape = scrape }
