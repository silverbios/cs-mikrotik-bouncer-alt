# MikroTik config

## Enable MikroTik RouterOS API

See [MikroTik RouterOS API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API)

## MikroTik user

Add user to MikroTik to allow access via RouterOS API.

```shell
/user group add name=crowdsec policy=api,read,write
/user add name=crowdsec-bouncer-user password=hunter2 group=crowdsec disabled=no
```

Remember to filter out access for the created user for given address only etc.

## Optional - Firewall rules with Log or Passthrough

To avoid unexpected issues it is advised to change the new rules to `passthrough`
so that you can see the number of packets that got through it.

Additional logging should help in checking if the setup works as expected.

If it works then change rules to `drop` one by one to make it actually workign
as expected :)

Below commands assume no logging and drop as default action.

## Firewall - IPv6 or IPv4

If you have dual-stacik (IPv6 and IPV4) available publicly, then enable both.
If you dont have one then it's better to use the only one you have, because
it speeds up device configuration and lowers consumed resources such as memory.

## Firewall - filter or raw

There is a difference between `firewall filter` and `firewall raw`, they serve
different purposes and require different computing powers - in short `filter`
is computationally heavier than `raw`, but allows doing more advanced traffic
filtering such as connection tracking and layer 7 protocol detection.

- raw drops packets as early as possible, and they are stateless
- raw is processed before filter rules, so it can save resources such as cpu
  and memory, especially if you are hitting device limits
- filter works after some other rules, like connection tracking
  and thus they are stateful and allow better manipulation of certain use cases
- using raw rules only should be done only when dealing with specific use cases
  such as DDOS (crowdsec is not really good at it, though)

Which one to choose?

- by default both are enabled, and first `raw` will drop most of the traffic,
  thus `filter` shoudl have much less to process and thus not consume that much
  resources if `raw` is not enabled.

- if the MikroTik device still struggles such as hitting limits of the cpu/memory
  of the device then try to use `raw` mode only.

## Creating Firewall filter rules

### Creating IPv6 firewall filter rules

For IPv6 - create IPv6 'drop' filter rules in `input` and `forward`
chain with the source address list set to `crowdsec` at the top.

Below are snippets to use, make sure to replace `ether1` with your desired interface.
Notice that if you use `place-before=0` then the order below is important,
and for `dst-address-list` we do not define interface.

```shell
/ipv6 firewall filter \
add action=drop dst-address-list=crowdsec chain=input \
place-before=0 comment="crowdsec input drop rules - dst"

/ipv6 firewall filter \
add action=drop dst-address-list=crowdsec chain=forward \
place-before=0 comment="crowdsec forward drop rules - dst"

/ipv6 firewall filter \
add action=drop src-address-list=crowdsec chain=input \
in-interface=ether1 \
place-before=0 comment="crowdsec input drop rules - src"

/ipv6 firewall filter \
add action=drop src-address-list=crowdsec chain=forward \
in-interface=ether1 \
place-before=0 comment="crowdsec forward drop rules - src"

```

The best would be to add them just after default `bad_ipv6` rules.

### Creating IPv4 firewall rules

For IPv4 - create IP `drop` filter rules in `input` and `forward` chain with the
source address list set to `crowdsec` at the top or just before
generic packet counter rule.

Below are snippets to use, make sure to replace `ether1` with your desired interface,
assuming that rule 0 is a dummy passthrough for packet counting added by default
to MikroTik, and rule 1 is whatever but we want to insert CrowdSec before it.
Notice that if you use `place-before=1` then the order below is important,
and for `dst-address-list` we do not define interface.

```shell
/ip firewall filter \
add action=drop dst-address-list=crowdsec chain=input \
place-before=1 comment="crowdsec input drop rules - dst"

/ip firewall filter \
add action=drop dst-address-list=crowdsec chain=forward \
place-before=1 comment="crowdsec forward drop rules - dst"

/ip firewall filter \
add action=drop src-address-list=crowdsec chain=input \
in-interface=ether1 \
place-before=1 comment="crowdsec input drop rules - src"

/ip firewall filter \
add action=drop src-address-list=crowdsec chain=forward \
in-interface=ether1 \
place-before=1 comment="crowdsec forward drop rules - src"

```

### List firewall filter rules

Get the list of firewall rules which were added, this will be needed later.

```shell
/ip firewall filter print without-paging

/ipv6 firewall filter print without-paging
```

Write down numbers of the rules on the most left column.

For example for IPv4:

```shell
> /ip firewall filter print without-paging

Flags: X - disabled, I - invalid; D - dynamic
 0  D ;;; special dummy rule to show fasttrack counters
      chain=forward action=passthrough

 1    ;;; crowdsec forward drop rules - src
      chain=forward action=drop src-address-list=crowdsec in-interface=ether1 log=no log-prefix=""

 2    ;;; crowdsec input drop rules - src
      chain=input action=drop src-address-list=crowdsec in-interface=ether1 log=no log-prefix=""

 3    ;;; crowdsec forward drop rules - dst
      chain=forward action=drop dst-address-list=crowdsec log=no log-prefix=""

 4    ;;; crowdsec input drop rules - dst
      chain=input action=drop dst-address-list=crowdsec log=no log-prefix=""

 5    ;;; defconf: accept established,related,untracked
      chain=input action=accept connection-state=established,related,untracked

 6    ;;; defconf: drop invalid
      chain=input action=drop connection-state=invalid

```

then:

- `IP_FIREWALL_FILTER_RULES_SRC` would be `1,2`
- `IP_FIREWALL_FILTER_RULES_DST` would be `3,4`

Similar, for IPv6:

```shell
> /ipv6 firewall filter print without-paging
Flags: X - disabled, I - invalid; D - dynamic
 0    ;;; crowdsec input drop rules - src
      chain=input action=drop src-address-list=crowdsec in-interface=ether1 log=no log-prefix=""

 1    ;;; crowdsec forward drop rules - src
      chain=forward action=drop src-address-list=crowdsec in-interface=ether1 log=no log-prefix=""

 2    ;;; crowdsec input drop rules - dst
      chain=input action=drop log=no log-prefix=""

 3    ;;; crowdsec forward drop rules - dst
      chain=forward action=drop log=no log-prefix=""

 4    ;;; defconf: drop invalid
      chain=input action=drop connection-state=invalid

 5    ;;; defconf: accept established,related,untracked
      chain=input action=accept connection-state=established,related,untracked
```

then:

- `IPV6_FIREWALL_FILTER_RULES_SRC` would be `0,1`
- `IPV6_FIREWALL_FILTER_RULES_DST` would be `2,3`

## Creating firewall raw rules

### Creating IPv6 firewall raw rules

For IPv6 - create IPv6 'drop' filter rules in `prerouting` and `output`
chain with the source/destination address list set to `crowdsec` at the top.

Below are snippets to use, make sure to replace `ether1` with your desired interface.
Notice that if you use `place-before=0` then the order below is important.

```shell
/ipv6 firewall raw \
add action=drop src-address-list=crowdsec chain=prerouting \
in-interface=ether1 \
comment="crowdsec prerouting drop rules - src"

/ipv6 firewall raw \
add action=drop dst-address-list=crowdsec chain=prerouting \
comment="crowdsec prerouting drop rules - dst"

/ipv6 firewall raw \
add action=drop dst-address-list=crowdsec chain=output \
comment="crowdsec output drop rules - dst"

```

The best would be to add them just after default `bad_ipv6` rules.

### Creating IPv4 firewall raw rules

For IPv4 - create IP `drop` filter rules in `prerouting` and `output` chain with the
source/destination address list set to `crowdsec` at the top or just before
generic packet counter rule.

Below are snippets to use, make sure to replace `ether1` with your desired interface,
assuming that rule 0 is a dummy passthrough for packet counting added by default
to MikroTik, and rule 1 is whatever but we want to insert CrowdSec before it.
Notice that if you use `place-before=1` then the order below is important.

```shell
/ip firewall raw \
add action=drop src-address-list=crowdsec chain=prerouting \
in-interface=ether1 \
comment="crowdsec prerouting drop rules - src"

/ip firewall raw \
add action=drop dst-address-list=crowdsec chain=prerouting \
comment="crowdsec prerouting drop rules - dst"

/ip firewall raw \
add action=drop dst-address-list=crowdsec chain=output \
comment="crowdsec output drop rules - dst"

```

### List firewall raw rules

Get the list of firewall rules which were added, this will be needed later.

```shell
/ip firewall raw print without-paging

/ipv6 firewall raw print without-paging
```

Write down numbers of the rules on the most left column.

For example for IPv4:

```shell
> /ip firewall raw print without-paging
Flags: X - disabled, I - invalid; D - dynamic
 0  D ;;; special dummy rule to show fasttrack counters
      chain=prerouting action=passthrough

 1    ;;; crowdsec prerouting drop rules - src
      chain=prerouting action=drop log=no log-prefix="" src-address-list=crowdsec_2025-07-06_12-50-38

 2    ;;; crowdsec output drop rules - dst
      chain=output action=drop log=no log-prefix="" dst-address-list=crowdsec_2025-07-06_12-50-38

 3    ;;; crowdsec prerouting drop rules - dst
      chain=prerouting action=drop log=no log-prefix="" dst-address-list=crowdsec

```

then:

- `IP_FIREWALL_RAW_RULES_DST` would be `2,3` (output,prerouting)
- `IP_FIREWALL_RAW_RULES_SRC` would be `1` (prerouting)

Similar, for IPv6:

```shell
> /ipv6 firewall raw print without-paging
Flags: X - disabled, I - invalid; D - dynamic
 0    ;;; crowdsec prerouting drop rules - src
      chain=prerouting action=drop in-interface=ether1 src-address-list=crowdsec

 1    ;;; crowdsec prerouting drop rules - dst
      chain=prerouting action=drop dst-address-list=crowdsec

 2    ;;; crowdsec output drop rules - dst
      chain=output action=drop dst-address-list=crowdsec


```

then:

- `IPV6_FIREWALL_RAW_RULES_DST` would be `1,2` (output,prerouting)
- `IPV6_FIREWALL_RAW_RULES_SRC` would be `0` (prerouting)
