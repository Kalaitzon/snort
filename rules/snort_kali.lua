HOME_NET = '10.0.0.0/24'
EXTERNAL_NET = '!10.0.0.0/24'
stream = { }
stream_tcp = { }
stream_icmp = { }
binder = { { when = { proto = 'tcp', ports = '8080' }, use = { type = 'http_inspect' } } }
http_inspect = { }
ips = { enable_builtin_rules = false }
alert_fast = { file = true }
