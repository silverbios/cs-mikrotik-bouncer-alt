# Deployment

Only Linux deployments were tested as golang binary or as app running in
containers such as Docker or k3s.

## Locally

Make sure to have a golang installed locally, build binary without running:

```shell
make binary
```

Compile and run - edit `.env` file and then

```shell
export $(cat .env | xargs)
go run .

```

This will compile golang to binary and execute it.

## Docker

I recommend using [docker-compose](https://github.com/nvtkaszpir/cs-mikrotik-bouncer-alt/tree/main/deploy/docker),
copy .env file there and start bouncer with

```shell
docker compose up
```

and investigate errors.

If you want to test observability stack, then run

```shell
cd deploy/docker
docker compose -f docker-compose-stack.yaml up
```

and it will spawn minimal example of the bouncer, prometheus and grafana with an imported
dashboard.

URLs to access services locally:

* [bouncer](http://127.0.0.1:2112/metrics)
* [prometheus](http://127.0.0.1:9090)
* [grafana](http://127.0.0.1:3000) user:pass `admin:admin`

The dasboard is imported only on grafana start so you can trigger container restart to reload
the symlinked dashboard.

## Kubernetes

Kustomization files in [kubernetes](https://github.com/nvtkaszpir/cs-mikrotik-bouncer-alt/tree/main/deploy/kubernetes)
via [kustomize](https://kustomize.io/) with optional ServiceMonitor
for automatic metric collections via Prometheus Operator.

I suggest to deploy a bouncer in a separate namespace for each target MikroTik device,
so it is easier to copy/paste kustomize base.

If needed, change in ServiceMonitor relabelings if you want to distinguish bouncers
in grafana (not implemented yet in the dashboard)

```yaml
...
  endpoints:
    - port: metrics
      scheme: http
      interval: 10s
      path: /metrics
      relabelings:
        - targetLabel: device # label key
          replacement: hap-ax-3 # label value

```
