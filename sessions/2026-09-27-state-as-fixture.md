# Session: State-as-Fixture Architecture Implemented (2026-09-27)

## What Changed

PRTA now uses the labgrid Strategy pattern for TollGate session state
management. Tests declare the state they need via function-scoped fixtures
instead of assuming it. This solved the test-ordering isolation issue.

## Key Commits (all on main, pushed to origin + amperstrand)

- `71c7da8` feat(stories): state-as-fixture pattern — test isolation solved
- `1fc7b95` feat(stories): contract validation tests
- `d422fce` feat(stories): V4/CBOR token payment, portal tabs
- `4a444ac` feat(contract): behavior contract JSON + contract-driven assertions
- `f33d8f8` merge: upstream main + all story work

## Architecture

Three new fixtures in tests/stories/conftest.py:
- `no_session` — guarantees device is UNAUTHENTICATED (portal visible)
- `fresh_session` — guarantees device is AUTHENTICATED (internet working)
- `rate_limiter` — session-scoped, backs off near backend's 10/min limit

Design doc: docs/session-state-management.md
Research: pytest fixture isolation patterns + labgrid Strategy fixtures

## Test Results

18/18 stories pass in sequence (45.5s), zero ordering failures.
Previously: 17/18 with 1 ordering-dependent failure.

## Labgrid Places

- `android-test` — phone mutex (AndroidADDDevice, ZY326DPC7R)
- `nr7101-router` — NR7101 router (NetworkService)
- `tollgate-s3-hil` — ESP32 S3 HIL (existing)

## Files Created

- tests/stories/conftest.py (state fixtures, device abstraction, labgrid mutex)
- tests/stories/test_user_pays_and_gets_internet.py
- tests/stories/test_session_expiry_and_repayment.py
- tests/stories/test_degraded_mode.py
- tests/stories/test_portal_tabs.py
- tests/stories/test_v4_token.py
- tests/stories/test_contract_validation.py
- config/behavior-contract.json
- lib/contract.py
- lib/clients/ssid.py
- lib/labgrid_topology.py
- config/labgrid-env.yaml
- scripts/run-stories.sh
- docs/session-state-management.md
- docs/authoritative-test-suite.md
- docs/labgrid-test-architecture.md
