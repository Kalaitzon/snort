---------------------------------------------------------------------
-- snort.lua - Snort 3 config (offline pcap analysis)
--
-- Usage (offline, from the project root):
--   snort -c rules/snort.lua -R rules/local.rules \
--         -r pcaps/lab_traffic.pcap -A alert_fast -l logs
--
-- The rules are loaded via the -R parameter (see SNORT_GUIDE.md),
-- so they are not included here (to avoid double loading / duplicate sid).
-- Produces logs/alert_fast.txt with one alert per line.
---------------------------------------------------------------------

HOME_NET = '10.0.0.0/24'
EXTERNAL_NET = '!10.0.0.0/24'

-- Minimal set of inspectors so that http_inspect / content matches work
stream = { }
stream_tcp = { }
stream_udp = { }
stream_icmp = { }

binder =
{
    { when = { proto = 'tcp', ports = '8080' }, use = { type = 'http_inspect' } },
    { use = { type = 'wizard' } },
}

http_inspect = { }
wizard = default_wizard

-- The rules are given with -R on the command line (rules/local.rules)
ips =
{
    enable_builtin_rules = false,
}

-- Output
alert_fast =
{
    file = true,
    packet = false,
}
