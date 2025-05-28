GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_SOURCE := $(shell git config --get remote.origin.url)
#QUAY_REPO_USER := kaszpir
#QUAY_REPO_NAME := quay.io/kaszpir/cs-mikrotik-bouncer:latest
KO_DOCKER_REPO ?= quay.io/kaszpir/

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '(^[0-9a-zA-Z_-]+:.*?##.*$$)|(^##)' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

.PHONY: version
version: ## show git version
	@echo GIT_COMMIT IS $(GIT_COMMIT)

.PHONY: debug
debug: ## run debug locally, loads env vars from .env
	export $$(cat .env | xargs) && go run . 2>&1| tee  out-$$(date +"%Y-%m-%d_%H-%M").log


.PHONY: image
image: ## build images
	ko build -B  --platform=linux/amd64,linux/arm64,linux/arm

.PHONY: fmt
fmt: ## go tile formatter
	go fmt ./...
