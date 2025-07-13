# TODO

This section is a list of things to do in the future or never :)

- change ServiceMonitor to PodMonitor, there is no need for a service, it's just
  metrics anyway

- try to run container on the mikrotik

- add automatic ticker interval adjustments?

- double check if there is an error after adding address, then if we try to
  update fw rule to new list:
  - if change to new list then it may be truncated ( missing entries)
  - if we keep to old list or don't add new list, then things can expire

- periodically ask MikroTik for `ip firewall address-list count-only` and make
  metric from it?

- [ko local](https://ko.build/configuration/)
  or `docker run -p 2112:2112 $(ko build ./cmd/app)` etc

- panic on no route to host in docker-compose up :D

- ip meging
  [ipaddres-go](https://github.com/seancfoley/ipaddress-go)
  will help to decrease number of address-list entries, and thus decrease time
  needed to perform an update, and lowers memory usage on the device

  from the basic experiment it was possible to decrease list size to 70% of initial
  lenght, but the downside is that the ttl would be strictly set to defined length
  such as 1h

  slurp all addresses from the cache and merge them,
  iterate over the output and inject to mikrotik
  but there are different ttl times so there would be a need to somehow extend/truncate them
  easier to extend by inserting max time
