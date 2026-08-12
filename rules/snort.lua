---------------------------------------------------------------------
-- snort.lua - Snort 3 config (offline pcap analysis)
-- Ioannis Kalaitzidis, MTE25012
--
-- Χρηση (offline, απο τη ριζα του project):
--   snort -c rules/snort.lua -R rules/local.rules \
--         -r pcaps/lab_traffic.pcap -A alert_fast -l logs
--
-- Οι κανονες φορτωνονται μεσω της παραμετρου -R (βλ. SNORT_GUIDE.md),
-- γι' αυτο δεν γινονται include εδω (αποφυγη διπλης φορτωσης / duplicate sid).
-- Παραγει logs/alert_fast.txt με ενα alert ανα γραμμη.
---------------------------------------------------------------------

HOME_NET = '10.0.0.0/24'
EXTERNAL_NET = '!10.0.0.0/24'

-- Ελαχιστο σετ inspectors ωστε να δουλευουν http_inspect / content matches
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

-- Οι κανονες δινονται με -R στη γραμμη εντολων (rules/local.rules)
ips =
{
    enable_builtin_rules = false,
}

-- Εξοδος
alert_fast =
{
    file = true,
    packet = false,
}
