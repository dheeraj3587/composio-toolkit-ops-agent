SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

PYTHON ?= python3.11
PIP := $(PYTHON) -m pip

.PHONY: help venv install-core install-providers install-dev install-browser \
	api web streamlit test lint typecheck compile audit frontend-check security docker-up

help: ## Show supported development commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

venv: ## Create the Python 3.11 virtual environment.
	$(PYTHON) -m venv .venv

install-core: ## Install the secure core, API, and local interfaces.
	$(PIP) install --requirement requirements.txt

install-providers: ## Install the pinned external provider adapters.
	$(PIP) install --requirement requirements-providers.txt

install-dev: ## Install the complete offline-safe development toolchain.
	$(PIP) install --requirement requirements-dev.txt
	cd web && npm ci --no-audit --no-fund

install-browser: ## Install the local Playwright Chromium runtime.
	$(PYTHON) -m playwright install chromium

api: ## Run the local FastAPI service with reload and local-only binding.
	$(PYTHON) -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

web: ## Run the Next.js development server.
	cd web && npm run dev

streamlit: ## Run the trusted internal Streamlit interface locally.
	$(PYTHON) -m streamlit run streamlit_app.py --server.address 127.0.0.1

test: ## Run normal offline-safe Python tests; live tests remain excluded.
	RUN_LIVE_TESTS=0 $(PYTHON) -m pytest -q

lint: ## Run Python lint and formatting verification.
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

typecheck: ## Run strict Python type checking.
	$(PYTHON) -m mypy ops api streamlit_app.py

compile: ## Compile Python sources without writing application state.
	$(PYTHON) -m compileall -q ops api streamlit_app.py

audit: ## Audit all Python and frontend dependencies.
	$(PYTHON) -m pip_audit -r requirements-dev.txt
	cd web && npm audit --audit-level=high

frontend-check: ## Run frontend lint, types, tests, and production build.
	cd web && npm run lint && npm run typecheck && npm run test && npm run build

security: ## Run the complete local security and quality gate.
	./scripts/security_gate.sh

docker-up: ## Build and run the loopback-only Compose stack.
	docker compose up --build
