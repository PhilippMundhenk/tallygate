# tallygate developer & operator shortcuts. `make help` lists targets.
SHELL := /bin/bash
COMPOSE ?= docker compose
PY ?= python3

.PHONY: help
help:  ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- development
.PHONY: dev-setup lint fmt test test-unit test-e2e
dev-setup:  ## install dev dependencies into the current Python env
	$(PY) -m pip install -r requirements-dev.txt shellcheck-py

lint:  ## ruff + shellcheck + vendored-file checksums
	ruff check .
	ruff format --check .
	shellcheck setup.sh agent/entrypoint.sh tests/integration/bypass.sh
	cd control/app/static/vendor && sha256sum --quiet -c SHA256SUMS

fmt:  ## auto-format
	ruff check --fix .
	ruff format .

test-unit:  ## policy engine unit tests
	$(PY) -m pytest tests/unit

test-e2e:  ## gateway/control/notification end-to-end tests (no Docker needed; ttyd optional)
	$(PY) -m pytest tests/e2e

test: test-unit test-e2e  ## all local tests

# ---------------------------------------------------------------- operations
.PHONY: setup build up down logs ps bypass-test password
setup:  ## first-time host setup (.env, secrets, state dirs)
	./setup.sh

build:  ## build all images
	$(COMPOSE) build

up:  ## start the stack
	$(COMPOSE) up -d --build

down:  ## stop the stack
	$(COMPOSE) down

logs:  ## follow logs
	$(COMPOSE) logs -f --tail=100

ps:  ## container status
	$(COMPOSE) ps

bypass-test:  ## authoritative isolation test against the running stack
	./tests/integration/bypass.sh

password:  ## generate a CONTROL_PASSWORD_HASH
	$(PY) control/hashpw.py
