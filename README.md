# conwrt

> **conwrt** — a safe, auditable framework for identifying network devices and supervising OpenWrt migrations.

> ⚠️ **DISCLAIMER**: conwrt is a research and prototyping framework. It is designed for safe, read-only device identification and supervised migration planning. Any device-specific flashing support **must be validated by a human operator before use**. You must have legal authority to probe any target network. The authors accept no liability for damage caused by unsupervised use.

## Status
Beta — automated flashing and configuration working for Linksys Velop WHW03 (V1/V2). 3 devices provisioned. See `scripts/auto-flash.py` and `recipes/linksys-whw03/`.

## Layout

```
conwrt/
├── docs/              # Process and redaction documentation
├── examples/          # Example run artifacts (redacted)
├── prompts/           # Step prompt templates (step-01 through step-04)
├── recipes/           # Device-specific migration recipes (placeholder)
├── runs/              # Runtime data (gitignored raw/, tracked redacted/)
├── schemas/           # JSON Schema definitions for all data shapes
├── scripts/           # Shell automation scripts
│   └── lib/           # Shared bash library
├── tests/             # Bats test suite
├── Makefile           # Build runner
└── README.md
```

## Quick Start

```bash
# 1. Initialize a new discovery run
make init ARGS="--target 192.168.1.1 --operator alice"

# 2. Execute step 1 (requires OpenCode or OPENCODE_CMD adapter)
make run-step ARGS="--run latest --step 01"

# 3. Redact output
make redact ARGS="--run latest"

# 4. Validate findings
make validate ARGS="--run latest"

# 5. Commit redacted artifacts to git
make commit-run ARGS="--run latest"
```

Each step in the workflow is idempotent. The `init` target creates a timestamped run directory under `runs/` and validates dependencies. `run-step` assembles a composite prompt from the run metadata and step template, then calls the LLM adapter. `redact` applies deterministic pattern replacement to strip sensitive identifiers. `validate` checks all `findings.json` files against their JSON schemas. `commit-run` stages only redacted artifacts, `findings.json`, and metadata, never raw output.

See [docs/process.md](docs/process.md) for the full step lifecycle and state machine details.

## Workflow
See [docs/process.md](docs/process.md).

## Redaction
See [docs/redaction.md](docs/redaction.md).

## Adapter Configuration

The LLM CLI is abstracted behind the `OPENCODE_CMD` environment variable. This lets you swap in any command-line tool that accepts a prompt file and produces structured output.

```bash
# Default (uses opencode CLI):
OPENCODE_CMD="opencode run --prompt-file"

# Override with your own LLM CLI adapter:
OPENCODE_CMD="my-llm-wrapper --prompt" make run-step ARGS="--run latest --step 01"
```

The adapter contract is simple: the command receives the composite prompt file path as its last argument, must write artifacts to `$STEP_DIR/raw/`, must write `$STEP_DIR/findings.json` matching the step-findings schema, and must exit 0 on success.

The adapter section in `scripts/run-step.sh` is clearly marked between `### ADAPTER START` and `### ADAPTER END` comments. To customize for a different LLM CLI, edit that block or set `OPENCODE_CMD` in your environment.

Environment variables `STEP_DIR` and `RUN_DIR` are passed to the adapter so it knows where to write output.

## Contributing

1. Fork the repo and create a feature branch.
2. Make your changes.
3. Run `make lint` and `make validate-schemas`. Both must pass before opening a PR.
4. Open a pull request against `main`.

A few ground rules:

- No flashing logic. conwrt is a read-only identification and planning framework. If you add destructive commands, the PR will be rejected.
- Keep the DISCLAIMER accurate. If your changes broaden the framework's scope, update the disclaimer to reflect the new capabilities and risks.
- Follow the existing code style: bash scripts checked with `bash -n`, JSON schemas validated with `ajv-cli@5`.
- Write tests for new scripts using the Bats suite under `tests/`.

## License
MIT — see [LICENSE](LICENSE).
