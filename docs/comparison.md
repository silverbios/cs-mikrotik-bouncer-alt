# Comparison to other solutions

## funkolabs/cs-mikrotik-bouncer

[Funkolabs version](https://github.com/funkolab/cs-mikrotik-bouncer)
tries to dynamically update addresses in address lists on the
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
  lagging behind the main update loop until there was a noticeable desynchronization
  which could be solved only by the app restart

- some people mitigated it with scheduled app restarts after few hours,
  effectively making cache not really useful

- in addition it kept constant connections to the MikroTik device, I am not sure
  how it handled network errors - maybe crashes in containers helped it to
  auto recover :)

This fork works differently:

- there is no need to fetch addresses from the MikroTik device at all

- listen for the decisions from Crowdsec LAPI and compare it with local cache

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

## Native CrowdSec and Mikrotik integration via API

As described at [docs integrations/mikrotik](https://docs.crowdsec.net/u/integrations/mikrotik/)
will be called `api-integration` below.

- `api-integration` requires MikroTik device to support ingesting blocklists.

- `api-integration` exposes list of currently blocked addresses only,
  and requires script on the MikroTik, wich will parse that imported blocklist.

- `api-integration` script on mikrotik first deletes existing addresses from
  address-list named `crowdsec-integration` and then inserts new entries
  Unfortunately address removal can be slow on certain devices.

- As of the current date (2025.07.06) only firewall filter is supported,
  anything else requires custom scripting.

See below for more details, which are shared with `crowdsecurity/cs-blocklist-mirror`.

## crowdsecurity/cs-blocklist-mirror

[crowdsecurity/cs-blocklist-mirror](https://github.com/crowdsecurity/cs-blocklist-mirror/tree/main/docker#mikrotik)

- `cs-blocklist-mirror` runs similarly to `api-integration` and requires
  MikroTik device to support ingesting blocklists and script on the device.

- `cs-blocklist-mirror` exposes web endpoint which allows to fetch address list
  and process it via script which runs on the MikroTik in scheduled intervals
  - this means that `cs-blocklist-mirror` runs let say once per hour.
  The script can be in plain ip address list (and custom scripting on MikroTik)
  or prepared script (golang template baked into the app).
  By default addresses are managed in single predefined address-list.
  Unfortunately address removal can be slow on certain devices.

- cs-mikrotik-bouncer-alt can run in scheduled intervals let say once per
  hour, just as tools above.

- cs-mikrotik-bouncer-alt can actively listen to the incoming streaming
  decisions from the CrowdSec LAPI and issue firewall update immediately, within
  seconds, and not minutes (depends on the config).

- cs-mikrotik-bouncer-alt creates new address list with active bans and then
  changes firewall rules to use new address list

- `cs-blocklist-mirror` can host single address list accessible from multiple devices
  at once, lists is in pull mode only

- cs-mikrotik-bouncer-alt manages single device in push mode,
  so each device needs separate running process (systemd service/container)
  to talk to remote MikroTik device.
