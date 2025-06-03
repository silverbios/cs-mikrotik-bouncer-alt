# CrowdSec MikroTik Bouncer Alternative

This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer
for the router [MikroTik](https://mikrotik.com) to block malicious IP to access your services.
For this it leverages [MikroTik API](https://mikrotik.com) to populate a dynamic Firewall Address List.

A fork of `CrowdSec Bouncer for MikroTik RouterOS appliance` by [funkolabs](https://github.com/funkolab/cs-mikrotik-bouncer),
but now living as standalone named as `Alternative` (or in short `alt`),
to avoid confusion with the original repo and related integrations.

Notice it works differently, some elements are common in the config, but
make sure to read carefully this readme file for more details.

```mermaid
sequenceDiagram
  participant CrowdSec API
  participant Bouncer
  participant Mikrotik

  Bouncer ->>+ CrowdSec API: login

  rect rgba(0, 0, 255, .25)
  loop Cache Update flow
    CrowdSec API ->>+ Bouncer: get decisions as stream<br/>insert/update/remove item into cache
    Bouncer ->>+ Bouncer: trigger mikrotik update if needed
  end
  end


  rect rgba(255, 255, 0, .25)
  loop Cache TTL
    Bouncer ->>+ Bouncer: auto remove expired items from cache due TTL
  end
  end

  rect rgba(255, 0, 0, .25)
  loop Mikrotik configuration: <br/>every 1h or on incoming decision
      Bouncer ->>+ Bouncer: create new address-list name
      Bouncer ->> Mikrotik: connection open

      loop over each item in the cache
          Bouncer ->> Mikrotik: insert address to new address-list with ttl 4h
      end
      Bouncer ->> Mikrotik: update firewall rule to use new address-list
      Bouncer ->> Mikrotik: connection close
  end
  end

  rect rgba(0, 255, 0, .25)
  loop Mikrotik address-list lifecycle: every 30s
    Mikrotik ->>+ Mikrotik: check if address in any address-list should expire
    Mikrotik ->>+ Mikrotik: if address-list empty then delete address-list
  end
  end

  loop Metrics
    Bouncer ->>+ Bouncer: update TTLCache metrics
  end

```

## Differences

Funkolabs version tries to dynamically update addresses in address lists on the
MikroTik device. This has some disadvantages:

- it fetches addresses from a single address-list from the routers,
  then used it as cache, meanwhile it was also listening to the decisions
  from the CrowdSec LAPI, and then tries to update the addresses in the MikroTik.
  So generally bouncer was doing a diff between upstream and MikroTik device,
  which is complex
- Doing `ip address find` on the MikroTik is slow, on certain devices this is
  **VERY** slow, making noticeable load on the CPU of the device
- above caused that some devices were not blocking addresses fast enough,
  or some addresses were not blocked at all, thus the diff process was
  lagging behind the main update loop until there was a noticeable desynch
- some people mitigated it with scheduled app restarts after few hours,
  effectively making cache not really useful
- in addition it kept constant connections to the MikroTik device, I am not sure
  how it handled network errors - maybe crashes in containers helped it to
  auto recover :)

This fork works differently:

- there is no need to fetch addresses from the MikroTik device at all
- listen for the decisions from Crowdsec LAPI and compare it with local cache,
- if there are differences between the cache such as add/delete/update
  then process the addresses
- in separate loop walk over addresses in local cache,
  and only then connect to the MikroTik device
- add address to a **NEW** address-list on the MikroTik,
  optionally prior inserting the address shorten expiry time to desired value
  to say 4h ( I named that as `truncate`) .
- if there were no errors then alter specific existing firewall rules to use
  that new address-list - the swap is quick and atomic

This way a new list it created on MikroTik device with addresses with updated
timeout values.

The old list will auto-expire after certain time, so it's good if this is short
living one say 4h - default basic CrowdSec configuration updates addresses
at least once per hour.

## Features

- set max time for ip address blocking - new decision comes in for 6 days,
  but this tool changes it to a series of update 4h bans in MikroTik
- faster operation, especially on older devices
- you can test it without affecting existing setup - creates new address-lists
  and updates specific firewall rules which can be disabled, thus easy to
  migrate from old to a new setup without breaking old configuration
- detailed messages in log, optionally plain text messages
- option to limit incoming decisions to desired value such as 2, to make it
  easier to test setups prior production
- separate loop to fetch decisions from the CrowdSec LAPI, which inserts
  addresses to the local cache
- separate loop to process addresses in the local cache and convert it to the
  commands to create new MikroTik address-list and firewall update command
  to use that newly created address-list
- prometheus metrics
- use locking in the app to prevent concurrent address-list insertion within the
  process (if you use concurrent bouncers then this still may happen anyway)

## Known limitations

- code executes commands against single MikroTik device, this is by design,
  and adding multi-device support is not planned due to the complexity.
  Just run separate app instances with different configs - this way you can
  much more easily test new configs on the same or different devices.
  The app eats very low amount of resources (about 10 miliCore/24MB in peak)

- incoming decisions are added to the cache in separate loop than items added
  to the Mikrotik, so there is a an about 10s delay between actual ip ban via
  csclu and the firwall update on the MikroTik device.

### TODO

- double check if there is an error after adding address, then if we try to
  update fw rule to new list:
  - if change to new list then it may be truncated ( missing entries)
  - if we keep to old list or dont add new list, then things can expire
- periodically ask MikroTik for `ip firewall address-list count-only` and make
  metric from it?
- add grafana dashboard
- k8s manifests
- [ko local](https://ko.build/configuration/)
  or `docker run -p 2112:2112 $(ko build ./cmd/app)` etc
- maybe mkdocs + gh pages?
- graceful shutdown, so that adding addresses and firewall is finished?

- panic on no route to host in docker-compose up :D

## Running

For now, this service is mainly fought to be used in as an app in a container.
If you need to build from source, you can get some inspiration from the Makefile
or section below.

## Prerequisites

You should have a MikroTik appliance and a CrowdSec instance running.
The container is available as docker image under [quay.io/kaszpir/cs-mikrotik-bouncer-alt](https://quay.io/kaszpir/cs-mikrotik-bouncer-alt).
The running contaner must have access to CrowdSec and to MikroTik.

# Configuration

Read below instructions below doing anything.
First we configure MikroTik device by adding user and firewall rules.
Then we create a bouncer in CrowdSec.
After that prepare config for the bouncer and start the app or container.

## MikroTik config

### MikroTik user

Add user to MikroTik to allow access via RouterOS API.

```shell
/user add name=crowdsec-bouncer-user password=hunter2 group=full disabled=no
```

Remember to filter out access for the created user for given address only etc.

### IPv6 firewall rules

For IPv6 - create IPv6 'drop' filter rules in `input` and `forward`
chain with the source address list set to `crowdsec` at the top.

Below are snippets to use, make sure to replace `ether1` with your desired interface:

```shell
/ipv6 firewall filter \
add action=drop src-address-list=crowdsec chain=input \
in-interface=ether1 \
place-before=0 comment="crowdsec input drop rules"

/ipv6 firewall filter \
add action=drop src-address-list=crowdsec chain=forward \
in-interface=ether1 \
place-before=0 comment="crowdsec forward drop rules"

```

The best would be to add them just after default `bad_ipv6` rules.

### IPv4 firewall rules

For IPv4 - create IP `drop` filter rules in `input` and `forward` chain with the
source address list set to `crowdsec` at the top or just before
generic packet counter rule.

Below are snippets to use, make sure to replace `ether1` with your desired interface,
assuming that rule 0 is a dummy passthrough for packet counting added by default
to MikroTik, and rule 1 is whatever but we want to insert CrowdSec before it:

```shell
/ip firewall filter \
add action=drop src-address-list=crowdsec chain=input \
in-interface=ether1 \
place-before=1 comment="crowdsec input drop rules"

/ip firewall filter \
add action=drop src-address-list=crowdsec chain=forward \
in-interface=ether1 \
place-before=1 comment="crowdsec forward drop rules"

```

### List firewall rules

Get the list of firewall rules which were added, this will be needed later.

```shell
/ip firewall filter print without-paging

/ipv6 firewall filter print without-paging
```

Write down numbers of the rules on the most left column.

For example for IPv4:

```text
> /ip firewall filter print without-paging

Flags: X - disabled, I - invalid; D - dynamic
 0  D ;;; special dummy rule to show fasttrack counters
      chain=forward action=passthrough

 1    ;;; crowdsec input drop rules
      chain=input action=drop src-address-list=crowdsec_2025-05-30_20-03-09 in-interface=ether1

 2    ;;; crowdsec forward drop rules
      chain=forward action=drop src-address-list=crowdsec_2025-05-30_20-03-09 in-interface=ether1

 3    ;;; defconf: accept established,related,untracked
      chain=input action=accept connection-state=established,related,untracked

 4    ;;; defconf: drop invalid
      chain=input action=drop connection-state=invalid

```

then your `IP_FIREWALL_RULES` would be `1,2`.

Similar, for IPv6:

```text
> /ipv6 firewall filter print without-paging
Flags: X - disabled, I - invalid; D - dynamic
 0    ;;; crowdsec forward drop rules
      chain=forward action=drop src-address-list=crowdsec_2025-05-29_20-37-42 in-interface=ether1

 1    ;;; crowdsec input drop rules
      chain=input action=drop src-address-list=crowdsec_2025-05-29_20-37-42 in-interface=ether1

 2    ;;; defconf: drop invalid
      chain=input action=drop connection-state=invalid

 3    ;;; defconf: accept established,related,untracked
      chain=input action=accept connection-state=established,related,untracked
```

then your `IPV6_FIREWALL_RULES` would be `0,1`.

### Prepare config for the app

Copy `env.dist` as `.env` and edit its content

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add),
get a bouncer API key from your CrowdSec with a command

```shell
cscli bouncers add mikrotik-bouncer
```

Copy the API key printed. You **WILL NOT** be able the get it again.
Paste this API key as the value for bouncer environment variable `CROWDSEC_BOUNCER_API_KEY`

Adjust other variables in .env file as needed, especially host to MikroTik
device and CrowdSec endpoint. See section below.

### Run the app

Start bouncer with `docker-compose up` and investigate errors.

# Configuration options

The bouncer configuration is made via environment variables:

- `CROWDSEC_BOUNCER_API_KEY` - default value: ``, required,
  CrowdSec bouncer API key required to be authorized to request local API.

- `CROWDSEC_URL` - default value: `http://crowdsec:8080/`, required,
  Host and port of CrowdSec LAPI agent.

- `CROWDSEC_ORIGINS` - default value: ``, optional,
  Space separated list of CrowdSec origins to filter from LAPI,
  in example `crowdsec cscli`.

- `DEBUG_DECISIONS_MAX` - default value: `-1`, optional,
  Set number of decisions to process at max, useful for debugging.
  Set to 3 to make things less spammy.

- `LOG_LEVEL` - default value: `1`, optional,
  Minimum log level for bouncer in [zerolog levels](https://pkg.go.dev/github.com/rs/zerolog#readme-leveled-logging)

- `LOG_FORMAT_JSON` - default value: `true`, optional,
  Use logs in JSON format, set to `false` for plain text zerolog format
  with key=value, useful only in certain debug sessions

- `MIKROTIK_HOST` - default value: ``, required,
  MikroTik device address to access RouterOS API ( `ip:port`)

- `MIKROTIK_USER` - default value: ``, required,
  Mikrotik device username to access RouterOS API

- `MIKROTIK_PASS` - default value: ``, required,
  Mikrotik device password to access RouterOS API

- `MIKROTIK_TLS` -  default value: `true`, optional,
  User TLS to connect to MikroTik API,

- `MIKROTIK_IPV4` - default value: `true`, optional,
  IPv4 support, set to `true` to enable processing IPv4 blocklists

- `IP_FIREWALL_RULES` - default value: ``, required if `MIKROTIK_IPV4` is set to true,
  comma separated numbers of IPv4 firewall rules to update on access-list change,
  those are created during configuration, for example `1,2` (input,forward)

- `MIKROTIK_IPV6` - default value: `true`,  optional,
  IPv6 support, set to `true` to enable processing IPv6 blocklists

- `IPV6_FIREWALL_RULES` - default value: ``, required if `MIKROTIK_IPV6` is set to true,
  comma separated numbers of IPv6 firewall rules to update on access-list change,
  those are created during configuration , for example `0,1` (input,forward)

- `MIKROTIK_ADDRESS_LIST` - default value: `crowdsec`, optional,
  prefix for target address-list in MikroTik device, no special chars,
  no spaces etc, generated name will be with a timestamp suffix,
  if you set it to `crowdsec` then access-list will be named as
  `crowdsec_2025-05-19_15-01-09` or something like it (UTC),

- `MIKROTIK_TIMEOUT` - default value: `10s`, optional,
  set timeout when trying to connect to the MikroTik,
  recommended to keep it under `60s`

- `MIKROTIK_TIMEOUT` - default value: `10s`, optional,
  set timeout when trying to connect to the MikroTik,
  recommended to keep it under `60s`

- `MIKROTIK_UPDATE_FREQUENCY` - default value: `1h`, optional,
  Set default frequency to update MikroTik address-lists and firewall rules.

- `USE_MAX_TTL` - default value: `false`, optional,
  Set to `true` if you want to truncate timeout for the address in address-list
  so that your address lists expire faster

- `DEFAULT_TTL_MAX` - default value: `24h`, optional,
  If USE_MAX_TTL is `true`  and new address timeout is above `DEFAULT_TTL_MAX`
  then that address will have timeout set to `USE_MAX_TTL` value.

  For example new decision comes in, and address should be banned for 4 days,
  but `DEFAULT_TTL_MAX=4h` will make it to be added with `timeout=4h`.
  Notice that the original 4 day ban will be respected in the application cache
  or from incoming CrowdSec decisions, but on MikroTik it will have 4h.

  Yet it is good to quickly expire old address-lists automatically, because
  new ones will come in with refreshed entries for the same address ips to block.

  Because CrowdSec publishes new lists at least once an hour then that address
  will be readded to the new list every hour until expires.

  This helps to avoid having thousands addresses in hundrets address-lists in
  the MikroTik.

  Recommended value is at least 3x longer than the frequency you get updates from
  the CrowdSec, so on basic setup 4h should be sufficient. For locations with
  possible network disruptions 8h or 16 would be recommended.

  For weaker/older devices it may be better to keep it really low like 2h.

  Must be longer than `MIKROTIK_UPDATE_FREQUENCY`.

- `TRIGGER_ON_UPDATE` - default value: `true`, optional,
  if you set it to true, then trigger mikrotik address-list and firewall update immediately
  (well, usually in about 5s).

  This makes ban added from other tools being applied faster, but for the
  price of creating new address-list and firewall update.
  Effectively you really want this enabled, and also have `USE_MAX_TTL` set to
  say 4h for quicker old address expiration.

  If set to `false` then the address will not be banned until the next loop
  of the `MIKROTIK_UPDATE_FREQUENCY` is executed, so on default settings it may
  take up to 1h before address is banned.

- `GOMAXPROCS` - default value: `` (automatic number of processors), optional,
  Set default processes to use by golang app, especially useful to prevent it
  from getting excessively throttled in the containers,
  Recommended value `1`.

- `METRICS_ADDRESS` - default value: `:2112`, optional,
  Address to use to start metrics server in Prometheus format, metrics are
  exposed under `/metrics` path, without authorization (not implemented).

# Metrics

If running locally see [http://127.0.0.1:2112/metrics](http://127.0.0.1:2112/metrics)

Some metrics appear after a while.
Most important ones:

- `mikrotik_cmd_total{result="error"}` - number of errors when trying to communicate with MikroTik
- `mikrotik_cmd_total{result="success"}` - number of commands succesfully executed on MikroTik
- `decisions_total{}` - processed incoming CrowdSec decisions to block/unblock addresses
- `truncated_ttl_total{}` - number of ban truncated because they were too long

# Contribution

For bigger changes please create an issue for discussion.
This helps in deciding if your work is worth doing because it may not be accepted,
due to various reasons.

Feel free to maintain your own fork :)

# Development

copy `env.dist` as `.env` and edit its values, then run:

```shell
export $(cat .env | xargs)
go run .

```

or if you want to also get the logs:

```shell
export $(cat .env | xargs)
go run . 2>&1| tee  out-$(date +"%Y-%m-%d_%H-%M").log
```

Build image using [ko](https://ko.build/)

```shell
export KO_DOCKER_REPO=quay.io/kaszpir/
ko build -B -t dev --platform=linux/amd64
docker-compose up
```

## Other MikroTik commands

```shell
/ip firewall address-list remove [find where list="crowdsec"]
/ipv6 firewall address-list remove [find where list="crowdsec"]

# drop specific matching crowdsec prefix for given day
/ip firewall address-list remove [find where list~"^crowdsec_2025-05-20_.*"]
/ipv6 firewall address-list remove [find where list~"^crowdsec_2025-05-20_.*"]


# drop all matching crowdsec prefix
/ip firewall address-list remove [find where list~"^crowdsec.*"]
/ipv6 firewall address-list remove [find where list~"^crowdsec.*"]

```
