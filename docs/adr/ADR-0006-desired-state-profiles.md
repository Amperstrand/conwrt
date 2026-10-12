# ADR 0006: Desired-state profiles and module composition

Status: accepted (schema provisional until M7 prototype)
Milestone: M7

## Context

Today's use-case presets (`scripts/use_cases/`, 34 modules, registry +
`ParamDef` validation + typed-ops pipeline rendered to shell or ubus) are the
seed of desired-state configuration. The 2.0 requirement is broader: the user
declares what a router should *be*; the engine decides whether that requires
config-only changes, package installs, a sysupgrade, or full recovery — and
can plan, preview, apply idempotently, verify, and detect drift.

Hard lessons already encoded in 1.x issues that the design must honor:
partial-apply dangers (#19, #21), rollback gaps (#17, #18), injection
validation (#25), silent install failures (#57), BusyBox uci constraints
(#56).

## Decision

1. **Profiles are declarative TOML** (versioned schema `profile.v1`) selecting
   composable **modules**; modules declare:
   - typed parameters (string/int/bool/enum/secret-ref) with validation,
   - required device capabilities + OpenWrt version/package constraints,
   - dependencies and **conflicts** with other modules,
   - preflight checks, apply operations (typed op IR, not shell strings),
   - verification probes (read-back + functional health),
   - rollback declaration — including *explicitly documented limits*
     (UCI-commit-on-UBIFS is unrecoverable; some states cannot be rolled
     back, and the plan must say so **before** applying).
2. **Secrets are references** (`secret://vpn-client`), resolved by the
   controller's `SecretStore` capability at apply time; never serialized into
   plans, logs, or wire messages (redaction is engine-level).
3. **The planner is engine-level**: input = current state (diagnosis) +
   desired state (profile) + model facts; output = ordered, reversible-annotated
   plan of `Op`s. `--dry-run` prints the plan with zero capability mutation —
   enforced by a mock-provider gate in tests (dry-run purity is an acceptance
   test, not a convention).
4. **Ops stay typed IR** (port of `profile/ops.py`): rendered to shell for
   SSH targets, ubus/rpcd JSON for HTTP transport, or first-boot scripts for
   image baking — one semantic, three renderings (1.x precedent, kept).
5. **Idempotence + drift**: apply is convergent (safe retry); `conwrt verify`
   re-runs probes and reports drift vs the recorded desired state.
6. **Migration**: each 1.x use case ports as a module with its `ParamDef`s
   mapped to typed params; test-status fields carry over so untested
   combinations stay visibly marked.
7. **TollGate is a profile/module that talks to its backend via the router's
   rpcd contract — never business logic in conwrt** (ADR-0007).

## Consequences

- The wizard UX becomes profile-agnostic: discover → diagnose → pick target →
  plan → authorize → apply → verify.
- Schema evolution is additive; profile files carry `schema_version`.
- Conflicts/rollback honesty requires module authors to think about failure
  up front — enforced by schema-required fields, not convention.

## Alternatives considered

- **Imperative scripts (status quo)**: rejected — no planning, no drift, no
  uniform wizard.
- **Full Nix-style declarative system state**: overkill — OpenWrt's UCI is
  the system of record; we reconcile rather than replace.
- **KCL/CUE-style external DSL**: rejected — TOML + typed params keeps the
  1.x authoring experience and the plugin simplicity.
