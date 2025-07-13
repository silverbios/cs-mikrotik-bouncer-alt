GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_SOURCE := $(shell git config --get remote.origin.url)
KO_DOCKER_REPO ?= quay.io/kaszpir/

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '(^[0-9a-zA-Z_-]+:.*?##.*$$)|(^##)' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

.PHONY: version
version: ## show git version
	@echo GIT_COMMIT IS $(GIT_COMMIT)

.PHONY: debug
debug: build ## run debug locally, loads env vars from .env
	export $$(cat .env | xargs) && ./cs-mikrotik-bouncer-alt 2>&1| tee  out-$$(date +"%Y-%m-%d_%H-%M").log

.PHONY: full
full: build ## run full setup locally, loads env vars from .env.full
	export $$(cat .env.full | xargs) && ./cs-mikrotik-bouncer-alt 2>&1| tee  out-$$(date +"%Y-%m-%d_%H-%M").log

.PHONY: image
image: ## build images
	ko build -B -t  $(GIT_COMMIT) --platform=linux/amd64,linux/arm64,linux/arm

.PHONY: fmt
fmt: ## go tile formatter
	go fmt ./...

.PHONY: lint
lint: fmt ## run golangci-lint
	golangci-lint run --fix

.PHONY: update
update: ## update golang deps
	go get -u
	go mod tidy
	go mod vendor

.PHONY: build
build: ## build binary into ./cs-mikrotik-bouncer-alt
	go build -o ./cs-mikrotik-bouncer-alt

.PHONY: clean
clean: ## delete log files and built binary
	rm -rf *.log
	rm -rf ./cs-mikrotik-bouncer-alt

.PHONY: docs
docs: ## run mkdocs serve
	mkdocs serve
