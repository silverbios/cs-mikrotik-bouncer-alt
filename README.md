<p align="center">
<img src="https://github.com/funkolab/cs-mikrotik-bouncer/raw/main/docs/assets/crowdsec_mikrotik_logo.png" alt="CrowdSec" title="CrowdSec" width="300" height="280" />
</p>

# CrowdSec Mikrotik Bouncer

A CrowdSec Bouncer for MikroTik RouterOS appliance

![GitHub](https://img.shields.io/github/license/funkolab/cs-mikrotik-bouncer)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/funkolab/cs-mikrotik-bouncer)
[![Go Report Card](https://goreportcard.com/badge/github.com/funkolab/cs-mikrotik-bouncer)](https://goreportcard.com/report/github.com/funkolab/cs-mikrotik-bouncer)
[![Maintainability](https://api.codeclimate.com/v1/badges/0104e64dccffc4b42f52/maintainability)](https://codeclimate.com/github/funkolab/cs-mikrotik-bouncer/maintainability)
[![ci](https://github.com/funkolab/cs-mikrotik-bouncer/actions/workflows/container-release.yaml/badge.svg)](https://github.com/funkolab/cs-mikrotik-bouncer/actions/workflows/container-release.yaml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/funkolab/cs-mikrotik-bouncer)
![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/funkolab/cs-mikrotik-bouncer)

# Description

This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer
for the router [Mikrotik](https://mikrotik.com) to block malicious IP to access your services.
For this it leverages [Mikrotik API](https://mikrotik.com) to populate a dynamic Firewall Address List.

# Usage

For now, this web service is mainly fought to be used as a container.
If you need to build from source, you can get some inspiration from the Dockerfile.

## Prerequisites

You should have a Mikrotik appliance and a CrowdSec instance running.
The container is available as docker image `ghcr.io/funkolab/cs-mikrotik-bouncer`.
It must have access to CrowdSec and to Mikrotik.

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add)

## Procedure

1. Get a bouncer API key from your CrowdSec with command `cscli bouncers add mikrotik-bouncer`
2. Copy the API key printed. You **_WILL NOT_** be able the get it again.
3. Paste this API key as the value for bouncer environment variable
   `CROWDSEC_BOUNCER_API_KEY`, instead of "MyApiKey"
4. Start bouncer with `docker-compose up bouncer` in the [./example](./example) directory
5. Create IP 'drop' filter rules in `input` and `forward` chain with the
   source address list set to `crowdsec` at the top or just before
   generic packet counter rule
6. If you yuse IPv6 then create IPv6 'drop' filter rules in `input` and `forward`
   chain with the source address list set to `crowdsec` at the top or just before
   generic packet counter rule

Below are snippets to use, make sure to replace `your-wan-interface`

```shell
/ip/firewall/filter/
add action=drop src-address-list=crowdsec chain=input \
  in-interface=your-wan-interface \
  place-before=0 comment="crowdsec input drop rules"
add action=drop src-address-list=crowdsec chain=forward \
  in-interface=your-wan-interface \
  place-before=0 comment="crowdsec forward drop rules"

/ipv6/firewall/filter/
add action=drop src-address-list=crowdsec chain=input \
  in-interface=your-wan-interface \
  place-before=0 comment="crowdsec input drop rules"
add action=drop src-address-list=crowdsec chain=forward \
  in-interface=your-wan-interface \
  place-before=0 comment="crowdsec forward drop rules"


/ip/firewall/filter/print short
```

## Configuration

The bouncer configuration is made via environment variables:

- `CROWDSEC_BOUNCER_API_KEY`
  CrowdSec bouncer API key required to be authorized to request local API,
  default value: ``,
  required

- `CROWDSEC_URL`
  Host and port of CrowdSec LAPI agent,
  default value: `http://crowdsec:8080/`,
  required

- `CROWDSEC_ORIGINS`
  Space separated list of CrowdSec origins to filter from LAPI,
  in example `crowdsec cscli`,
  default value: ``,
  optional

- `DEBUG_DECISIONS_MAX`
  Set number of decisions to process at max, useful for debugging.
  default value: `-1`,
  optional

- `LOG_LEVEL`
  Minimum log level for bouncer in [zerolog levels](https://pkg.go.dev/github.com/rs/zerolog#readme-leveled-logging)
  default value: `1`
  optional

- `MIKROTIK_HOST`
  Mikrotik appliance address
  default value: ``,
  required

- `MIKROTIK_USER`
  Mikrotik appliance username
  default value: ``,
  required

- `MIKROTIK_PASS`
  Mikrotik appliance password
  default value: ``,
  required

- `MIKROTIK_TLS`
  User TLS to connect to Mikrotik API
  not tested yet :D
  default value: `true`,
  optional

- `MIKROTIK_IPV4`
  IPv4 support, set to `true` to enable processing IPv4 blocklists
  default value: `true`
  optional

- `IP_FIREWALL_RULES`
  comma separated numbers of IPv4 firewall rules to update on access-list change,
  those are created during configuration, for example `1,2` (input,forward)
  default value: ``
  required
  required if `MIKROTIK_IPV4` is set to true

- `MIKROTIK_IPV6`
  IPv6 support, set to `true` to enable processing IPv6 blocklists
  default value: `true`
  optional

- `IPV6_FIREWALL_RULES`
  comma separated numbers of IPv6 firewall rules to update on access-list change,
  those are created during configuration , for example `3,4` (input,forward),
  actually not tested :D
  default value: ``
  required if `MIKROTIK_IPV6` is set to true

- `MIKROTIK_ADDRESS_LIST`
  prefix for target address-list in mikrotik device, no special chars,
  no spaces etc, generated name will be with timestamp suffix,
  if you set it to `crowdsec` then access-list will be named as
  `crowdsec_2025-05-19_15-01-09` or something like it (UTC),
  default value: `crowdsec`
  optional

- `MIKROTIK_TIMEOUT`
  set timeout when trying to connect to the mikrotik
  default value: `10s`
  optional

- `DEFAULT_TTL`
  Set default Time-To-Live for address if not provided,
  mainly needed to avoid getting extremely long dynamic and
  non-expiring firewall address-lists,
  default value: `1h`
  optional

- `GOMAXPROCS`
  Set default processes to use by golang app, especially useful to prevent it
  from getting excessively throttled in the containers
  default value: automatic number of processors
  optional
  recommended value `1`

- `METRICS_ADDRESS`
  Address to use to start metrics server in Prometheus format, metrics are
  exposed under `/metrics` path, without authorization (not implemented)
  default value: `:2112`,
  optional,

# Contribution

Any constructive feedback is welcome, fill free to add an issue or a pull request.
I will review it and integrate it to the code.

# Development

copy env.dist as .env and edit its values, then run:

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
export KO_DOCKER_REPO=bagno.hlds.pl:16000/kaszpir/cs-mikrotik-bouncer
ko build -B -t dev --platform=linux/amd64
docker-compose up
```

## Mikrotik commands

```shell
/ip firewall address-list remove [find where list="crowdsec"]
/ipv6 firewall address-list remove [find where list="crowdsec"]


# drop all matching crowdsec prefix
/ip firewall address-list remove [find where list~"^crowdsec.*"]
/ipv6 firewall address-list remove [find where list~"^crowdsec.*"]

```
