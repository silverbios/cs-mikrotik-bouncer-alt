# Known limitations

- code executes commands against single MikroTik device, this is by design,
  and adding multi-device support is not planned due to the complexity.
  Just run separate app instances with different configs - this way you can
  much more easily test new configs on the same or different devices.
  The app eats very low amount of resources (about 10 miliCore/24MB in peak)

- incoming decisions are added to the cache in separate loop than items added
  to the Mikrotik, so there is a an about 10s delay between actual IP ban via
  `cscli` and the firewall update on the MikroTik device.

- there is no graceful shutdown,
  in worst case address-list is half populated but not applied to firewall,
  or applied only to for example IPv4 (or IPv6),
  so the old address list is still active, and when the new process spawns then
  it will create a new list anyway

- tested with RouterOS 7.18.2, other versions

- using TLS to talk to Mikrotik RouterOS API was not tested yet
