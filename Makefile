SHELL := /bin/bash
SCRIPTS_DIR := scripts
SCHEMAS_DIR := schemas

.PHONY: help lint validate-schemas init run-step redact validate commit-run test smoke clean

help: ## Show this help
	@echo "Usage: make [target] [ARGS='...']"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

lint: ## Check shell scripts syntax (bash -n)
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

test: ## Run bats test suite (tests/)
	@if ! command -v bats >/dev/null 2>&1; then \
		echo "bats-core is not installed. Install with: npm install -g bats-core"; \
		exit 1; \
	fi
	@if [ ! -d tests ]; then \
		echo "tests/ directory not yet created (Wave 3 T17 will create it)."; \
		exit 0; \
	fi
	@bats tests/

smoke: ## End-to-end smoke test
	@if [ ! -f tests/smoke.sh ]; then \
		echo "smoke test not yet created"; \
		exit 0; \
	fi
	@bash tests/smoke.sh

clean: ## Remove .tmp files from runs/
	@echo "Cleaning .tmp directories..."
	@find runs/ -type d -name '.tmp' -exec rm -rf {} + 2>/dev/null || true
	@echo "Done."
