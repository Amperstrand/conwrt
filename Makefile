SHELL := /bin/bash
SCRIPTS_DIR := scripts
SCHEMAS_DIR := schemas

.PHONY: help lint typecheck validate-schemas validate-models init run-step redact validate commit-run test smoke ci ipk clean integration bench e2e

help: ## Show this help
	@echo "Usage: make [target] [ARGS='...']"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

lint: ## Run ruff and shell script syntax checks
	@echo "Running ruff..."
	@ruff check scripts tests
	@echo "Linting shell scripts..."
	@FAIL=0; \
	for f in $(SCRIPTS_DIR)/*.sh $(SCRIPTS_DIR)/lib/*.sh; do \
		if [ -f "$$f" ]; then \
			if ! bash -n "$$f"; then \
				echo "FAIL: $$f"; \
				FAIL=1; \
			else \
				echo "  OK: $$f"; \
			fi; \
		fi; \
	done; \
	if [ "$$FAIL" -ne 0 ]; then exit 1; fi

typecheck: ## Run Python static type checking
	@pyright scripts tests

validate-schemas: ## Compile all JSON schemas with ajv-cli@5
	@echo "Validating schemas..."
	@FAIL=0; \
	for s in $(SCHEMAS_DIR)/*.schema.json; do \
		if ! npx -y ajv-cli@5 compile -s "$$s"; then \
			echo "FAIL: $$s"; \
			FAIL=1; \
		else \
			echo "  OK: $$s"; \
		fi; \
	done; \
	if [ "$$FAIL" -ne 0 ]; then exit 1; fi

validate-models: ## Validate all models/*.json against schemas/model.schema.json
	@python3 scripts/validate_models.py

init: ## Initialize a new run (wraps scripts/init-run.sh)
	@echo "Initializing run..."
	@$(SCRIPTS_DIR)/init-run.sh $(ARGS)
## Usage: make init ARGS="--target 192.168.1.1 --operator alice"

run-step: ## Execute a step (wraps scripts/run-step.sh)
	@echo "Running step..."
	@$(SCRIPTS_DIR)/run-step.sh $(ARGS)
## Usage: make run-step ARGS="--run-id <id> --step <step>"

redact: ## Redact run output (wraps scripts/redact-output.sh)
	@echo "Redacting output..."
	@$(SCRIPTS_DIR)/redact-output.sh $(ARGS)

validate: ## Validate findings JSON (wraps scripts/validate-findings.sh)
	@echo "Validating findings..."
	@$(SCRIPTS_DIR)/validate-findings.sh $(ARGS)

commit-run: ## Commit redacted artifacts (wraps scripts/commit-run.sh)
	@echo "Committing run artifacts..."
	@$(SCRIPTS_DIR)/commit-run.sh $(ARGS)

test: ## Fast unit tier (~1 min): excludes QEMU-backed integration tests
	@pytest tests -m "not integration"
	@pytest tests/integration/test_use_cases_dry_run.py -q
	@$(MAKE) smoke
	@if command -v bats >/dev/null 2>&1; then \
		bats tests/*.bats; \
	else \
		echo "bats-core is not installed; skipping bats tests (smoke still ran)"; \
	fi

test-all: ## Everything `test` runs plus QEMU integration tests inline (KVM hosts only)
	@pytest tests
	@$(MAKE) smoke

bg-integration: ## Fire-and-forget: launch the VM suite detached; verdict lands in test-results/history.md
	@mkdir -p test-results
	@setsid bash -c 'make integration >> test-results/bg-integration.log 2>&1; echo "bg-integration exit=$$? $$(date -Is)" >> test-results/bg-integration.log' < /dev/null > /dev/null 2>&1 &
	@echo "integration launched detached — log: test-results/bg-integration.log, verdicts: test-results/history.md"

stability5: ## Fire-and-forget: 5 consecutive integration runs for stability banking
	@mkdir -p test-results
	@setsid bash -c 'for i in 1 2 3 4 5; do echo "=== stability5 RUN $$i $$(date -Is) ===" >> test-results/stability5.log; make integration >> test-results/stability5.log 2>&1 && echo "RUN $$i: PASS" >> test-results/stability5.log || echo "RUN $$i: FAIL" >> test-results/stability5.log; done; echo "stability5 DONE $$(date -Is)" >> test-results/stability5.log' < /dev/null > /dev/null 2>&1 &
	@echo "5× integration launched detached — log: test-results/stability5.log, verdicts: test-results/history.md"

integration: ## Run full QEMU OpenWrt VM integration suite locally (results in test-results/)
	@bash scripts/local-tests.sh integration

bench: ## Run bufferbloat benchmark against local QEMU VM (results in test-results/)
	@bash scripts/local-tests.sh bench

e2e: ## Run hardware e2e tests (requires CONWRT_DEVICE_IP; results in test-results/)
	@bash scripts/local-tests.sh e2e
smoke: ## End-to-end smoke test
	@if [ ! -f tests/smoke.sh ]; then \
		echo "smoke test not yet created"; \
		exit 0; \
	fi
	@bash tests/smoke.sh

ci: ## Run all hardware-safe CI checks
	@$(MAKE) lint
	@$(MAKE) typecheck
	@$(MAKE) validate-schemas
	@$(MAKE) validate-models
	@$(MAKE) test

ipk: ## Build conwrt ipk for OpenWrt
	@$(SCRIPTS_DIR)/build_ipk.sh --output dist $(ARGS)

clean: ## Remove .tmp files from runs/
	@echo "Cleaning .tmp directories..."
	@find runs/ -type d -name '.tmp' -exec rm -rf {} + 2>/dev/null || true
	@echo "Done."
