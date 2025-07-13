# CrowdSec MikroTik Bouncer Alternative

![MikroTik plus CrowdSec](static/mikrotik_plus_crowdsec_small_800.png)

## Disclaimer

This project is not affiliated in any way with CrowdSec nor MikroTik,
use at your own risk.

## About

This repository aims to implement the [MikroTik](https://mikrotik.com) router as
[CrowdSec](https://doc.crowdsec.net/) Remediation Component (formerly known as bouncer),
thus making it easier to block malicious IP to access your services.
For this it leverages [MikroTik API](https://mikrotik.com) to populate a dynamic Firewall Address List.

This started as a fork of `CrowdSec Bouncer for MikroTik RouterOS appliance` by [funkolabs](https://github.com/funkolab/cs-mikrotik-bouncer),
but now it is living as standalone project, named as `Alternative` (or in short `alt`),
to avoid confusion with the original repo and related integrations.

Notice it works differently, some elements are common in the config, so the migration is quite easy,
but make sure to read carefully this readme file for more details.

## Architecture

### App architecture

```mermaid
sequenceDiagram
  participant CrowdSec API
  participant Bouncer
  participant Mikrotik

  Bouncer ->>+ CrowdSec API: login

  rect rgba(0, 0, 255, .25)
  loop Cache Update flow
    CrowdSec API ->>+ Bouncer: get decisions as stream<br/>insert/update/remove item into cache
    Bouncer ->>+ Bouncer: trigger MikroTik update if needed
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

## Example appliances

### Processing syslog logs from MikroTik

```mermaid
sequenceDiagram
  IP 1.2.3.4 ->> Mikrotik: incoming request
  Mikrotik ->> Log processor: send syslog messages from firewall
  Log processor ->> Log processor: detect port scans
  Log processor ->> Crowdsec LAPI: malicious activity detected for IP 1.2.3.4
  Crowdsec LAPI ->> Crowdsec LAPI: ban 1.2.3.4
  Crowdsec LAPI ->> Mikrotik Bouncer: stream bans
  Mikrotik Bouncer ->> Mikrotik: update address lists, block 1.2.3.4
  IP 1.2.3.4 --x  Mikrotik: drop traffic
```

### Blocking traffic at the edge

```mermaid
sequenceDiagram
  IP 1.2.3.4 --> Mikrotik: incoming request
  Mikrotik ->> Load Balancer: NAT traffic for web
  Load Balancer ->> Web server pool: lad balance traffic to web servers
  Web server pool ->> Crowdsec LAPI: malicious activity detected for IP 1.2.3.4
  Crowdsec LAPI ->> Crowdsec LAPI: ban 1.2.3.4
  Crowdsec LAPI ->> Mikrotik Bouncer: stream bans
  Mikrotik Bouncer ->> Mikrotik: update address lists, block 1.2.3.4
  IP 1.2.3.4 --x  Mikrotik: drop traffic
```
