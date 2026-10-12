# ADR 0009: Device models, specimen inventory, topology, and execution evidence

Status: accepted
Milestone: M1 (model types), continuous

## Context

AGENTS.md draws a hard line: conwrt is **species-level** (models, recipes,
flash methods — public, in git); **specimen-level** data (unit MACs, serials,
bench IPs, credentials) belongs in the operator's private project
(`Amperstrand/conwrt-lab` registry, labgrid places). 1.x additionally
produces execution evidence (flash timelines, inventory.jsonl as a local
cache). The 2.0 type system must keep these four concerns distinct so the
public repo can never leak private data and the engine can still gate on
specimen identity.

## Decision

1. **`conwrt-types::DeviceModel`** (species) parses today's `models/*.json`
   unchanged. Schema tightening is incremental and versioned: the JSON Schema
   gains optional *typed* sections (`signatures`, `flash_methods.*.params`)
   while `additionalProperties` stays true during migration; the Rust types
   carry `#[serde(flatten)] extras` for unknown fields so old/new files both
   parse.
2. **`conwrt-types::SpecimenRef`** (specimen) is a *reference type only*:
   MAC, serial, model_id, and a `RegistryRef` (opaque locator for the private
   registry). The engine never embeds specimen data in public artifacts;
   lint/redaction tests enforce it (extends 1.x `docs/redaction.md`
   practice).
3. **Identity gate is engine-level**: destructive operations require a
   resolved `SpecimenRef` whose MAC matches the live link evidence (port of
   the AGENTS.md MAC/serial gate + 1.x `_verify_device_identity`
   board-identity check — both, layered).
4. **Topology (bench/lab)** is resolved from the private registry via a
   `TopologyResolver` capability (implemented by the conwrt-bench/labgrid
   adapters), never hardcoded (AGENTS.md rule: no device IPs/MACs in code).
5. **Execution evidence**: append-only run records (JSONL) local to the
   executor: model_id, specimen ref, requested plan hash, per-step outcomes,
   image sha256, firmware provenance. Same schema the 1.x run-metadata JSON
   Schema sketches (`schemas/run-metadata.schema.json`) — carried forward,
   versioned.

## Consequences

- Public/private boundary is enforced by types + tests, not by diligence.
- Model JSON stays the shared 1.x/2.x asset (ADR-0001) while gaining typed
  sections over time.
- The engine's identity gate composes: link MAC (live) ↔ specimen (registry)
  ↔ board identity (device) — three independent witnesses before a flash.

## Alternatives considered

- **Migrate models to TOML/RCS now**: rejected — 24 files + device-matrix
  generation + 1.x tooling all read JSON; conversion is churn without
  benefit. Revisit only if schema versioning demands it.
- **Specimen inventory inside conwrt**: rejected — restates AGENTS.md's
  private-project rule.
