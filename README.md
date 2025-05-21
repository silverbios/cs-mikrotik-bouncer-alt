# CrowdSec Mikrotik Bouncer

A fork of CrowdSec Bouncer for MikroTik RouterOS appliance.

# Description

This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer
for the router [Mikrotik](https://mikrotik.com) to block malicious IP to access your services.
For this it leverages [Mikrotik API](https://mikrotik.com) to populate a dynamic Firewall Address List.

For now, this service is mainly fought to be used in debug mode executed locally
or as a container.
If you need to build from source, you can get some inspiration from the Makefile
or section below.

## Prerequisites

You should have a Mikrotik appliance and a CrowdSec instance running.
The container is available as docker image `quay.io/kaszpir/cs-mikrotik-bouncer`.
It must have access to CrowdSec and to Mikrotik.

# Configuration

Read below instructions below doing anything.
First we configure mikrotik device by adding firewall rules.
Then we create a bouncer in crowdsec.
After that prepare config for the bouncer and start the app or container.

## Mikrotik config

### Mikrotik user

Add user to mikrotik to allow access via RouterOS API.

```shell
/user add name=crowdsec-bouncer-user password=hunter2 group=full disabled=no
```

Remember to filter out access for the created user for given address only etc.

### IPv6 firewall rules

For IPv6 - create IPv6 'drop' filter rules in `input` and `forward`
chain with the source address list set to `crowdsec` at the top or just before
generic packet counter rule.

Below are snippets to use, make sure to replace `your-wan-interface`,
assuming that rule 0 is a dummy passthrough for packet counting added by default
to mikrotik

```shell
/ipv6 firewall filter \
add action=drop src-address-list=crowdsec chain=input \
  in-interface=your-wan-interface \
  place-after=0 comment="crowdsec input drop rules"

/ipv6 firewall filter \
add action=drop src-address-list=crowdsec chain=forward \
  in-interface=your-wan-interface \
  place-after=0 comment="crowdsec forward drop rules"

```

### IPv4 firewall rules

For IPv4 - create IP 'drop' filter rules in `input` and `forward` chain with the
source address list set to `crowdsec` at the top or just before
generic packet counter rule.

Below are snippets to use, make sure to replace `your-wan-interface`,
assuming that rule 0 is a dummy passthrough for packet counting added by default
to mikrotik

```shell
/ip firewall filter \
add action=drop src-address-list=crowdsec chain=input \
  in-interface=your-wan-interface \
  place-after=0 comment="crowdsec input drop rules"

/ip firewall filter \
add action=drop src-address-list=crowdsec chain=forward \
  in-interface=your-wan-interface \
  place-after=0 comment="crowdsec forward drop rules"

```

### List firewall rules

Get the list of firewall rules, this will be needed later.

```shell
/ip firewall filter print short

/ipv6 firewall filter print short
```

### Prepare config for the app

Copy `env.dist` as `.env` and edit its content

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add),
get a bouncer API key from your CrowdSec with a command

```shell
cscli bouncers add mikrotik-bouncer
```

Copy the API key printed. You **WILL NOT** be able the get it again.
Paste this API key as the value for bouncer environment variable `CROWDSEC_BOUNCER_API_KEY`

Adjust other variables in .env file as needed, especially host to Mikrotik
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
  Mikrotik device address to access RouterOS API ( `ip:port`)

- `MIKROTIK_USER` - default value: ``, required,
  Mikrotik device username to access RouterOS API

- `MIKROTIK_PASS` - default value: ``, required,
  Mikrotik device password to access RouterOS API

- `MIKROTIK_TLS` -  default value: `true`, optional,
  User TLS to connect to Mikrotik API,

- `MIKROTIK_IPV4` - default value: `true`, optional,
  IPv4 support, set to `true` to enable processing IPv4 blocklists

- `IP_FIREWALL_RULES` - default value: ``, required if `MIKROTIK_IPV4` is set to true,
  comma separated numbers of IPv4 firewall rules to update on access-list change,
  those are created during configuration, for example `1,2` (input,forward)

- `MIKROTIK_IPV6` - default value: `true`,  optional,
  IPv6 support, set to `true` to enable processing IPv6 blocklists

- `IPV6_FIREWALL_RULES` - default value: ``, required if `MIKROTIK_IPV6` is set to true,
  comma separated numbers of IPv6 firewall rules to update on access-list change,
  those are created during configuration , for example `3,4` (input,forward)

- `MIKROTIK_ADDRESS_LIST` - default value: `crowdsec`, optional,
  prefix for target address-list in mikrotik device, no special chars,
  no spaces etc, generated name will be with a timestamp suffix,
  if you set it to `crowdsec` then access-list will be named as
  `crowdsec_2025-05-19_15-01-09` or something like it (UTC),

- `MIKROTIK_TIMEOUT` - default value: `10s`, optional,
  set timeout when trying to connect to the mikrotik,
  recommended to keep it under `60s`

- `DEFAULT_TTL` - default value: `1h`, optional,
  Set default Time-To-Live for address if not provided,
  mainly needed to avoid getting extremely long dynamic and
  non-expiring firewall address-lists, and addresses without expiry

- `USE_MAX_TTL` - default value: `false`, optional,
  Set to `true` if you want to truncate timeout for the address in address-list
  so that your address lists expire faster

- `DEFAULT_TTL_MAX` - default value: `24h`, optional,
  If USE_MAX_TTL is `true`  and new address timeout is above `DEFAULT_TTL_MAX`
  then that address will have timeout set to `USE_MAX_TTL` value.

  For example new decision comes in, and address should be banned for 4 days,
  but `DEFAULT_TTL_MAX=4h` will make it to be added with `timeout=4h`.
  Notice that the original 4 day ban will be respected in the application cache
  or from incoming CrowdSec decisions, but on mikrotik it will have 4h.

  Yet it is good to quickly expire old address-lists automatically, because
  new ones will come in with refreshed entries for the same address ips to block.

  Because CrowdSec publishes new lists at least once an hour then that address
  will be readded to the new list every hour until expires.

  This helps to avoid having thousands addresses in hundrets address-lists in
  the mikrotik.

  Recommended value is at least 3x longer than the frequency you get updates from
  the CrowdSec, so on basic setup 4h should be sufficient. For locations with
  possible network disruptions 8h or 16 would be recommended.

  For weaker/older devices it may be better to keep it really low like 2h.

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

- `mikrotik_cmd_total{result="error"}` - number of errors when trying to communicate with mikrotik
- `mikrotik_cmd_total{result="success"}` - number of commands succesfully executed on mikrotik
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

## Other Mikrotik commands

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

## TODO

- add grafana dashboard
- [ko local](https://ko.build/configuration/)
  or `docker run -p 2112:2112 $(ko build ./cmd/app)` etc
- ko release fix in github action to push to quay
- maybe mkdocs + gh pages?
- graceful shutdown
