# Features

- set max time for IP address blocking - new decision comes in for 6 days,
  but this tool changes it to a series of update 4h bans in MikroTik

- faster operation than other project, especially on older devices

- you can test it without affecting existing setup - creates new address-lists
  and updates specific firewall rules which can be disabled, thus easy to
  migrate from old to a new setup without breaking old configuration

- detailed messages in log, optionally plain text messages

- option to limit incoming decisions to desired value such as maximum 2 bans
  to process, to make it easier to test setups prior production

- separate loop to fetch decisions from the CrowdSec LAPI, which inserts
  addresses to the local cache

- separate loop to process addresses in the local cache and convert it to the
  commands to create new MikroTik address-list and firewall update command
  to use that newly created address-list

- use locking in the app to prevent concurrent address-list insertion within the
  process (if you use concurrent bouncers then this still may happen anyway)

- create connection to the MikroTik only if update is needed

- designed to run in container without any privileges, read only container

- allow specifying blocking on the `filter firewall` or `filter raw` rules.
  Using `filter raw` is faster and more performant, but it may not suit
  all scenarios, see below for more details.

- prometheus metrics, which allows you to use grafana dashboards

![grafana_dashboard_1](static/grafana_dashboard_1-fs8.png)
