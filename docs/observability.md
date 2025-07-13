# Observability

For the detailed params see [configuration options](config.bouncer.md#configuration-options).

## Logging

Not much to say about logs.

JSON log format by default, so formatting it in Loki should be more conveniet.

Debug level floods a bit.

## Metrics

If running locally see [http://127.0.0.1:2112/metrics](http://127.0.0.1:2112/metrics)

Some metrics appear after a while (usually under 60s).

![grafana_dashboard_1](static/grafana_dashboard_1-fs8.png)

Grafana dashboard source is in the repo under `observability/grafana/CrowdSec_bouncer-mikrotik.json`

Most important metrics:

- `mikrotik_client_total{func="connect", result="error"}` - number of errors
  when trying to log in with MikroTik, especially when trying to connect,
  see app logs for more details

- `mikrotik_cmd_total{result="error"}` - number of errors when trying to run commands
   on with MikroTik after succesful logging in.

- `mikrotik_cmd_total{result="success"}` - number of commands successfully executed on MikroTik

- `decisions_total{}` - processed incoming CrowdSec decisions to block/unblock addresses,
  notice this does not mean they are added to the MikroTik, but to the app cache in memory.

- `truncated_ttl_total{}` - number of ban truncated because they were too long

- `mikrotik_cmd_duration_total` - duration of the commands executed when doing an update,
  for example when using HAP AX3 this should usually be about 10 to 15 seconds per update
  for inserting about 15.000 addresses to a new address-list

- `lock_wait_duration_total` - time spent for waiting for the lock to run commands to update
  a Mikrotik device, in general this should be microseconds, unless there is an existing update
  and there is a lot of decisions to be processed.
  There are two options to adjust - TICKER_INTERVAL, TRIGGER_ON_UPDATE, MIKROTIK_UPDATE_FREQUENCY.
