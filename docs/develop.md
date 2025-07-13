# Contribution

For bigger changes please create an issue for discussion.
This helps in deciding if your work is worth doing because it may not be accepted,
due to various reasons.

Feel free to maintain your own fork :)

## Local Development

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

### Build binary

```shell
make binary
```

### Build container image

Build image using [ko](https://ko.build/):

```shell
export KO_DOCKER_REPO=quay.io/kaszpir/
make image
# edit deploy/docker/docker-compose.yaml such as image/tag
docker-compose up
```

### Other MikroTik commands

```shell
/ip firewall address-list remove [find where list="crowdsec"]
/ipv6 firewall address-list remove [find where list="crowdsec"]

# drop specific matching crowdsec prefix for given day
/ip firewall address-list remove [find where list~"^crowdsec_2025-05-20_.*"]
/ipv6 firewall address-list remove [find where list~"^crowdsec_2025-05-20_.*"]


# drop all matching crowdsec prefix
/ip firewall address-list remove [find where list~"^crowdsec.*"]
/ipv6 firewall address-list remove [find where list~"^crowdsec.*"]

# list ALL addresses in address-list, meaning any ip in address lists,
# public addresses for lan/wan etc
/ip firewall address-list print count-only
/ipv6 firewall address-list print count-only

# list ip in given address list (slow, memory/cpu intensive)
/ip firewall address-list print brief without-paging   where list=crowdsec_2025-07-06_17-02-24

# show just count of the ip addresses in given address list (slow, memory/cpu intensive)
/ip firewall address-list print brief without-paging  count-only where list=crowdsec_2025-07-06_17-02-24
```

## Release

### Preparation

- before release run `make image` locally, will build and push image to quay
- test image for few hours.

### Actual Release

- merge to master/main
- push tag - will trigger github action of building image
- prepare github release with details, especially about breaking changes
