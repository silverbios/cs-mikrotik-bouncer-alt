# Tuning configuration

Depending on the device and your needs you can configure env vars to make blocking
faster or less resource consuming.

Some suggestions:

* if you don't use IPv6 then disable it via [MIKROTIK_IPV6=false](config.mikrotik.md#mikrotik_ipv6)

* devices which have low memory available should use [firewall raw only](config.mikrotik.md#firewall---filter-or-raw)

* if device cpu usage is high and it processes address-list updates slowly,
  or there is noticeable lock wait increase
  then try to increase [TICKER_INTERVAL](config.bouncer.md#ticker_interval)

* force faster addresses expiration from address-lists - it lowers memory usage,
  see [USE_MAX_TTL](config.bouncer.md#use_max_ttl) and [DEFAULT_TTL_MAX](config.bouncer.md#default_ttl_max)

* if the device still struggles try to disable [TRIGGER_ON_UPDATE](config.bouncer.md#trigger_on_update)

## Example configurations

### HAP AX3

```shell
DEFAULT_TTL_MAX=4h
GOMAXPROCS=1
IP_FIREWALL_FILTER_RULES_DST=5,6
IP_FIREWALL_FILTER_RULES_SRC=3,4
IP_FIREWALL_RAW_RULES_DST=2,3
IP_FIREWALL_RAW_RULES_SRC=1
IPV6_FIREWALL_FILTER_RULES_DST=2,3
IPV6_FIREWALL_FILTER_RULES_SRC=0,1
IPV6_FIREWALL_RAW_RULES_DST=1,2
IPV6_FIREWALL_RAW_RULES_SRC=0
LOG_LEVEL=0
MIKROTIK_FIREWALL_FILTER_ENABLE=true
MIKROTIK_FIREWALL_RAW_ENABLE=true
MIKROTIK_HOST=192.168.1.1:8728
MIKROTIK_IPV6=false
MIKROTIK_TLS=false
TICKER_INTERVAL=15s
USE_MAX_TTL=true
```
