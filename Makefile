# SPDX-License-Identifier: MIT
.DEFAULT_GOAL := help

HA_TAG := $(shell python3 -c "import tomllib; cfg=tomllib.load(open('config/ha_target.toml','rb')); print(cfg['docker']['ha_image_tag'])")
SANDBOX_IMAGE := hacs-engine-sandbox
SANDBOX_TAG   := latest

.PHONY: help sandbox fixtures test lint typecheck

help:          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

# ── Docker sandbox ────────────────────────────────────────────────────────────

sandbox:       ## Build the F-5 sandbox Docker image and run health tests
	docker build \
	  --build-arg HA_TAG=$(HA_TAG) \
	  -t $(SANDBOX_IMAGE):$(SANDBOX_TAG) \
	  docker/sandbox/
	docker run --rm $(SANDBOX_IMAGE):$(SANDBOX_TAG)

sandbox-build: ## Build the sandbox image only (no test run)
	docker build \
	  --build-arg HA_TAG=$(HA_TAG) \
	  -t $(SANDBOX_IMAGE):$(SANDBOX_TAG) \
	  docker/sandbox/

# ── Fixture corpus ────────────────────────────────────────────────────────────

fixtures:      ## Download APKs listed in fixtures/sources.yaml to fixtures/_cache/
	uv run python scripts/download_fixtures.py

# ── Dev loop ──────────────────────────────────────────────────────────────────

test:          ## Run the full test suite
	uv run pytest -ra --tb=short

lint:          ## Ruff lint check
	uv run ruff check src/ tests/

typecheck:     ## Mypy strict type-check
	uv run mypy src/
