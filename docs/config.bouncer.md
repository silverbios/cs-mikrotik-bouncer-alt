
# Prepare config for the app

Copy `env.dist` as `.env` and edit its content environmental variables.

## Register bouncer in Crowdsec LAPI

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add),
get a bouncer API key from your CrowdSec with a command

```shell
cscli bouncers add mikrotik-bouncer
```

Copy the API key printed. You **WILL NOT** be able the get it again.
Paste this API key as the value for bouncer environment variable `CROWDSEC_BOUNCER_API_KEY`

## Set firewall rules to control

In previous steps you can get the required firewall rules which will be used to
be updated.

Adjust other variables in .env file as needed, especially host to MikroTik
device and CrowdSec endpoint. See section below.

## Configuration options

The bouncer configuration is made via environment variables.

TODO: use golang docstring generator to list env vars and settings

### CROWDSEC_BOUNCER_API_KEY

`CROWDSEC_BOUNCER_API_KEY` - default value: unset, required,
CrowdSec bouncer API key required to be authorized to request local API.

### CROWDSEC_URL

`CROWDSEC_URL` - default value: `http://crowdsec:8080/`, required,
Host and port of CrowdSec LAPI agent.

### CROWDSEC_ORIGINS

`CROWDSEC_ORIGINS` - default value: unset, optional,
Space separated list of CrowdSec origins to filter from LAPI,
in example `crowdsec cscli`.

### DEBUG_DECISIONS_MAX

`DEBUG_DECISIONS_MAX` - default value: `-1`, optional,
Set number of decisions to process at max, useful for debugging.
Set to 3 to make things less spammy.

### LOG_LEVEL

`LOG_LEVEL` - default value: `1`, optional,
Minimum log level for bouncer in [zerolog levels](https://pkg.go.dev/github.com/rs/zerolog#readme-leveled-logging)

### LOG_FORMAT_JSON

`LOG_FORMAT_JSON` - default value: `true`, optional,
Use logs in JSON format, set to `false` for plain text zerolog format
with key=value, useful only in certain debug sessions

### MIKROTIK_HOST

`MIKROTIK_HOST` - default value: unset, required,
MikroTik device address to access RouterOS API ( `ip:port`)

### MIKROTIK_USER

`MIKROTIK_USER` - default value: unset, required,
Mikrotik device username to access RouterOS API

### MIKROTIK_PASS

`MIKROTIK_PASS` - default value: unset, required,
Mikrotik device password to access RouterOS API

### MIKROTIK_TLS

`MIKROTIK_TLS` -  default value: `true`, optional,
User TLS to connect to MikroTik API,

### MIKROTIK_IPV4

`MIKROTIK_IPV4` - default value: `true`, optional,
IPv4 support, set to `true` to enable processing IPv4 blocklists

### MIKROTIK_IPV6

`MIKROTIK_IPV6` - default value: `true`,  optional,
IPv6 support, set to `true` to enable processing IPv6 blocklists

### MIKROTIK_FIREWALL_FILTER_ENABLE

`MIKROTIK_FIREWALL_FILTER_ENABLE` - default value: `true`, optional,
enable updating firewall filter rules (filter input, forward, output)
See [Firewall Filter or Raw](config.mikrotik.md#firewall---filter-or-raw) for more details.

### IP_FIREWALL_FILTER_RULES_SRC

`IP_FIREWALL_FILTER_RULES_SRC` - default value: unset, required if `MIKROTIK_IPV4` is set to true,
comma separated numbers of IPv4 firewall filter rules to update on access-list change,
and to set src-address-list in it,
those are created during configuration, for example `1,2` (filter input, forward, output)

### IP_FIREWALL_FILTER_RULES_DST

`IP_FIREWALL_FILTER_RULES_DST` - default value: unset, required if `MIKROTIK_IPV4` is set to true,
comma separated numbers of IPv4 firewall filter rules to update on access-list change,
and to set dst-address-list in it,
those are created during configuration, for example `3,4` (filter input, forward, output)

### IPV6_FIREWALL_FILTER_RULES_SRC

`IPV6_FIREWALL_FILTER_RULES_SRC` - default value: unset, required if `MIKROTIK_IPV6` is set to true,
comma separated numbers of IPv6 firewall filter rules to update on access-list change,
and to set src-address-list in it,
those are created during configuration , for example `0,1` (filter input, forward, output)

### IPV6_FIREWALL_FILTER_RULES_DST

`IPV6_FIREWALL_FILTER_RULES_DST` - default value: unset, required if `MIKROTIK_IPV6` is set to true,
comma separated numbers of IPv6 firewall filter rules to update on access-list change,
and to set dst-address-list in it,
those are created during configuration , for example `2,3` (filter input, forward, output)

### MIKROTIK_FIREWALL_RAW_ENABLE

`MIKROTIK_FIREWALL_RAW_ENABLE` - default value: `true`, optional,
enable updating firewall raw rules (raw prerouting, output).
See [Firewall Filter or Raw](config.mikrotik.md#firewall---filter-or-raw) for more details.

### IP_FIREWALL_RAW_RULES_SRC

`IP_FIREWALL_RAW_RULES_SRC` - default value: unset, required if `MIKROTIK_IPV4` is set to true,
comma separated numbers of IPv4 firewall raw rules to update on access-list change,
and to set src-address-list in it,
those are created during configuration, for example `1` (raw prerouting, output)

### IP_FIREWALL_RAW_RULES_DST

`IP_FIREWALL_RAW_RULES_DST` - default value: unset, required if `MIKROTIK_IPV4` is set to true,
comma separated numbers of IPv4 firewall raw rules to update on access-list change,
and to set dst-address-list in it,
those are created during configuration, for example `2` (raw prerouting, output)

### IPV6_FIREWALL_RAW_RULES_SRC

`IPV6_FIREWALL_RAW_RULES_SRC` - default value: unset, required if `MIKROTIK_IPV6` is set to true,
comma separated numbers of IPv6 firewall raw rules to update on access-list change,
and to set src-address-list in it,
those are created during configuration , for example `0` (raw prerouting, output)

### IPV6_FIREWALL_RAW_RULES_DST

`IPV6_FIREWALL_RAW_RULES_DST` - default value: unset, required if `MIKROTIK_IPV6` is set to true,
comma separated numbers of IPv6 firewall raw rules to update on access-list change,
and to set dst-address-list in it,
those are created during configuration , for example `1` (raw prerouting, output)

### MIKROTIK_ADDRESS_LIST

`MIKROTIK_ADDRESS_LIST` - default value: `crowdsec`, optional,
prefix for target address-list in MikroTik device, no special chars,
no spaces etc, generated name will be with a timestamp suffix,
if you set it to `crowdsec` then access-list will be named as
`crowdsec_2025-05-19_15-01-09` or something like it (local time),

### MIKROTIK_TIMEOUT

`MIKROTIK_TIMEOUT` - default value: `10s`, optional,
set timeout when trying to connect to the MikroTik,
recommended to keep it under `60s`

### MIKROTIK_UPDATE_FREQUENCY

`MIKROTIK_UPDATE_FREQUENCY` - default value: `1h`, optional,
Set default frequency to update MikroTik address-lists and firewall rules.
This is useful if you have very low [DEFAULT_TTL_MAX](#default_ttl_max) value.

This is useful if you have disabled [TRIGGER_ON_UPDATE](#trigger_on_update),
or enabled `USE_MAX_TTL=true` and set [DEFAULT_TTL_MAX](#default_ttl_max).

### USE_MAX_TTL

`USE_MAX_TTL` - default value: `false`, optional,
Set to `true` if you want to truncate timeout for the address in address-list
so that your address lists expire faster

### DEFAULT_TTL_MAX

`DEFAULT_TTL_MAX` - default value: `4h`, optional,
If [USE_MAX_TTL](#use_max_ttl) is `true`  and new address timeout is above
[DEFAULT_TTL_MAX](#default_ttl_max) then that address will have timeout
set to [USE_MAX_TTL](#use_max_ttl) value.

For example new decision comes in, and address should be banned for 4 days,
but `DEFAULT_TTL_MAX=4h` will make it to be added with `timeout=4h`.
Notice that the original 4 day ban will be respected in the application cache
or from incoming CrowdSec decisions, but on MikroTik it will have 4h.

Yet it is good to quickly expire old address-lists automatically, because
new ones will come in with refreshed entries for the same address IPs to block.

Because CrowdSec publishes new lists at least once an hour then that address
will be readded to the new list every hour until expires.

This helps to avoid having thousands addresses in hundreds address-lists in
the MikroTik.

Recommended value is at least 2x longer than the frequency you get updates from
the CrowdSec, so on basic setup 4h should be sufficient. For locations with
possible network disruptions 8h or 16 would be recommended
(but then why ban if there is no internet? :) ).

For weaker/older devices it may be better to keep it really low like 2h.

If you get frequent updates from your CrowdSec LAPI (say every 5 minutes),
and you have [TRIGGER_ON_UPDATE=true](#trigger_on_update), then
you could even set it to as low as 15min.

Must be longer than [MIKROTIK_UPDATE_FREQUENCY](#mikrotik_update_frequency).

### TRIGGER_ON_UPDATE

`TRIGGER_ON_UPDATE` - default value: `true`, optional,
if you set it to true, then trigger MikroTik address-list and firewall update
immediately (look at [TICKER_INTERVAL](#ticker_interval)).

This makes ban added from other tools being applied faster, but for the
price of creating new address-list and firewall update.
Effectively you really want this enabled, and also have [USE_MAX_TTL](#use_max_ttl)
set to say 4h for quicker old address expiration.

If set to `false` then the address will not be banned until the next loop
of the [MIKROTIK_UPDATE_FREQUENCY](#mikrotik_update_frequency) is executed,
so on default settings it may take up to 1h before address is banned.

### TICKER_INTERVAL

`TICKER_INTERVAL` - default value: `10s`, optional
how frequently process streamed decisions from CrowdSec LAPI,

Notice this is a golang [time.Duration](https://pkg.go.dev/time#Duration)
format, but the value cannot be equal or less than `0s`.

This will vary depending on the current length of the IP addresses
to be blocked - so for example if you test with 4k addresses inserted and it
takes 10s then adding 20k addresses may take more (let say 25s).

The best if this is the total time used to update MikroTik
address lists and firewall plus about 30% just to prevent bouncer stuck waiting
to acquire lock for the update.

If you get frequent delays in acquiring lock then try to increase this value
higher, certain devices are quite slow and they need at least `30s` or `60s`
for processing.

Sometimes it is just better to buy better faster hardware.

### GOMAXPROCS

`GOMAXPROCS` - default value: unset (automatic number of processors), optional,
Set default processes to use by golang app, especially useful to prevent it
from getting excessively throttled in the containers,
Recommended value `1`.

### METRICS_ADDRESS

`METRICS_ADDRESS` - default value: `:2112`, optional,
Address to use to start metrics server in Prometheus format, metrics are
exposed under `/metrics` path, without authorization (not implemented).

### TZ

`TZ` - default value: unset, optional,
set desired timezone, otherwise if empty then it will take local time from
the machine it runs on. It affects logging and name of the address-list
suffix created on the MikroTik device. Example `UTC` or `Europe/Warsaw`.
