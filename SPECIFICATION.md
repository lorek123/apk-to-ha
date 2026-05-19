# HACS Integration Engine — Specification

> An autonomous pipeline that ingests an Android `.apk`, statically reverse-engineers its device communication contract, and emits a Home Assistant Community Store (HACS) integration that meets HA's Platinum quality scale.

---

## 1. Goals and non-goals

### Goals
- Take an `.apk` as input, produce a working HACS integration as output.
- Cover four communication paths: HTTP REST, BLE/GATT, TCP socket, and local UDP/zeroconf discovery.
- Generate integrations that pass `hassfest` and target HA Core's current Platinum quality scale rules.
- Self-correct via deterministic validation + agentic review + autonomous feedback from HA's own runtime logs.
- Refuse to duplicate work: detect existing HA Core / HACS integrations and bail out early.

### Non-goals
- Dynamic instrumentation as the primary extraction path. Frida is a fallback for crypto signing only, not the main strategy.
- Cloud-only / OAuth-heavy device APIs as the M1 target. Local-network HTTP comes first.
- Bypassing DRM, license enforcement, or anti-tamper. The engine analyzes communication protocols, not security mechanisms.
- A general-purpose APK analysis tool. Scope is narrow: device-control surfaces that map onto HA entities.

---

## 2. System overview

```
                       [target.apk]
                            │
                            ▼
       ┌─────────────────────────────────────────┐
       │ P1  Ingestion & framework classification │  JADX MCP
       └────────────────────┬────────────────────┘
                            ▼
       ┌─────────────────────────────────────────┐
       │ P2  Static network contract extraction   │  Retrofit/OkHttp/BLE scan
       └────────────────────┬────────────────────┘
                            ▼
       ┌─────────────────────────────────────────┐
       │ P-2.5  Existing integration check        │  HA Core + HACS index
       └────────────────────┬────────────────────┘   (bail if duplicate)
                            ▼
       ┌─────────────────────────────────────────┐
       │ P3  OpenAPI schema synthesis             │
       └────────────────────┬────────────────────┘
                            ▼
       ┌─────────────────────────────────────────┐
       │ P4  Standalone async Python SDK          │  aiohttp / bleak
       └────────────────────┬────────────────────┘
                            ▼
       ┌─────────────────────────────────────────┐
       │ P5  HACS component scaffold              │  hacs.integration_blueprint
       └────────────────────┬────────────────────┘
                            ▼
       ┌─────────────────────────────────────────┐
       │ V-tier  Autonomous validation loop       │  (see §5)
       └─────────────────────────────────────────┘
```

The pipeline is orchestrated by Claude Code. Deterministic tools (JADX, hassfest, ruff, Docker) are wrapped as MCP servers. LLM reasoning is reserved for tasks that require it: crypto signing trace, schema synthesis, rule-rubric judgment, fix-routing decisions.

---

## 3. Foundation tier

These must land before generation work begins.

### F-0 — Tool setup automation
Devcontainer-first, setup-script fallback. Pre-installs all toolchain dependencies at pinned versions. The devcontainer is the canonical development environment; `scripts/setup.sh` exists for users who can't run Docker for development.
- **Done when:** `./scripts/setup.sh smoke` runs end-to-end against a demo fixture and produces a valid HACS skeleton.

### F-0a — `ha-tooling` MCP server
FastMCP-based Python server exposing `run_ruff`, `run_mypy`, `run_hassfest`, `run_pytest` as MCP tools. Each returns structured JSON, not stderr scraping. Replaces ad-hoc subprocess wrappers.
- **Done when:** Claude Code can invoke each tool against a generated integration and parse the result.

### F-0b — `sandbox` MCP server
Wraps the V-3 Docker container test. Tools: `launch_ha_container(version)`, `install_integration(path)`, `configure(mock_device_spec)`, `capture_logs(timeout_s)`, `tear_down()`. State is per-session.
- **Done when:** a fixture integration can be loaded and its logs returned via MCP calls.

### F-1 — Repository scaffolding *(this ticket — partially complete)*
Monorepo layout, `pyproject.toml`, CI workflow, ruff + mypy + pytest configured.

### F-1a — License files
`LICENSE` (MIT), `NOTICE`, `CONTRIBUTING.md` with standard inbound-license clause.

### F-1b — SPDX headers
`# SPDX-License-Identifier: MIT` on every source file in the engine and on every file the engine emits. Non-negotiable for any future HA Core upstream contribution.

### F-2a — Snapshot harness
Tool that takes a local APK and produces a committable snapshot bundle: decompiled method bodies relevant to tests, `AndroidManifest.xml` excerpts, expected-IR JSON, expected-OpenAPI YAML. Distilled extracts only; no APK redistribution.
- **Done when:** APK → snapshot → IR round-trips on one fixture.

### F-2b — Corpus assembly
Source 6–10 APKs covering: 2× Native Java/Kotlin Retrofit, 1× Native OkHttp, 1× Tuya clone, 1× Flutter, 1× React Native, 1× BLE-only. Annotate each in `fixtures/sources.yaml` with license, source URL, and the framework branch it exercises. Run F-2a against each, commit results.
- **Done when:** corpus covers all framework branches with golden expected outputs.

### F-5 — Sandbox Docker base
Build the Docker image used in V-3 *now*. Python 3.14, ruff, mypy, pytest, HA Core 2026.5.x, the generated SDK output dir mounted.
- **Done when:** `docker run sandbox pytest` works against a stub.

### F-6 — Structured logging and run telemetry
JSON-line output, not free-text. Required fields per entry: `run_id`, `phase`, `step`, `level`, `message`, `duration_ms`, phase-specific context. For LLM calls also: prompt hash, response hash, model, tokens-in/out, latency, cost estimate. Runs land in `/runs/{run_id}/log.jsonl`. CLI `replay_run {run_id}` reconstructs state from logs.
- **Done when:** a failed run can be diagnosed entirely from its `/runs/{run_id}/` directory.

### F-7 — HA version targeting
Single source of truth at `config/ha_target.toml` declaring `ha_core_version`, `python_version`, `quality_scale_target`. All emitters consult it. V-3 pulls the matching Docker image. Anchor integrations are snapshotted from that release tag specifically, not HEAD.

Update path: weekly GitHub Action checks for a newer HA release, opens a PR bumping the pin, runs the full fixture suite, auto-merges if green. Flags broken patterns otherwise.
- **Done when:** changing `ha_core_version` propagates correctly through manifest emission and container tests.

---

## 4. Generation pipeline

### Phase 1 — Ingestion and framework classification

**P1-1 — JADX MCP integration.** Spawn/manage a JADX MCP server (default: `zinja-coder/jadx-ai-mcp`), wrap its query API in a typed Python client. Handle process lifecycle, decompilation timeouts, workspace dir cleanup.
- **Deps:** F-0. **Done when:** given an APK path, "list classes matching pattern X" returns structured results.

**P1-2 — Tuya pre-flight check.** Scan for `com.tuya.*` / `com.thingclip.*` packages. On hit, halt the pipeline and emit a "use tinytuya" advisory.
- **Deps:** P1-1. **Done when:** the Tuya fixture triggers the early-exit cleanly.

**P1-3 — Framework classifier.** Decision tree over decompiled-tree signatures: Flutter assets → Flutter; `index.android.bundle` → React Native; otherwise → Native. For M1 only the Native branch is implemented.
- **Deps:** P1-1. **Done when:** every fixture classifies correctly.

**P1-4 — AndroidManifest parser.** Pull permissions, services, `NsdManager` references, intent filters into a typed structure.
- **Deps:** P1-1.

**P1-5 — Flutter path (M3).** Integrate `blutter` (or `reFlutter` for older AOT formats), extract string literals and symbol names. Expect lower extraction quality than Native; document the gap.

**P1-6 — React Native path (M3).** Extract and unminify `index.android.bundle`, AST-traverse to find fetch/axios call sites and URL literals.

### Phase 2 — Static contract extraction

> **Evaluation note:** before implementing P2-1..P2-3 from scratch, evaluate `vichhka-git/android-reverse-engineering-mcp-server` against the fixture corpus. It claims Retrofit + OkHttp + auth header extraction out of the box. If it works, lean on it.

**P2-1 — Retrofit/OkHttp annotation scanner.** Find all `@POST`/`@GET`/`@PUT`/`@DELETE`/`@Headers` annotations and extract path + verb + header arrays.
- **Deps:** P1-1, P1-3. **Done when:** ≥95% of expected endpoints recovered from Native fixtures.

**P2-2 — Payload class resolver.** For each `@Body` parameter and method return type, walk the class definition and extract `@SerializedName`/`@Json(name=...)` mappings into a typed `PayloadSchema`. Handle nested classes and collections.
- **Deps:** P2-1. **Done when:** serialized field names match fixture expectations.

**P2-3 — Header & auth pattern extractor.** Identify static headers vs dynamically-injected ones (typically via OkHttp Interceptor classes). For M1 just flag dynamic injection; defer tracing to P2-5.
- **Deps:** P2-1.

**P2-4 — Crypto API scanner.** Find imports/usages of `javax.crypto.Mac`, `MessageDigest.getInstance(...)`, and common HMAC libraries.
- **Deps:** M1 complete.

**P2-5 — Signing-input tracer (LLM-assisted).** For each crypto call site, trace string concatenation backwards through method calls to identify the input format (e.g., `timestamp + path + body + secret`). LLM reasons over decompiled method bodies; output is a structured trace.
- **Deps:** P2-4, F-0. **Highest-risk ticket in the project.** Plan for 60–70% success rate on first attempt across fixtures. Hand-off path to P2-7 when low-confidence.

**P2-6 — Signature algorithm Python emitter.** Given a P2-5 trace, generate the corresponding Python signing function plus a unit test verifying it matches an example from the trace.
- **Deps:** P2-5, P4-1.

**P2-7 — Frida dynamic verification fallback.** When P2-5 confidence is low or P2-6's emitted signer fails verification, launch the app in an emulator with a Frida hook, capture a real request, validate or correct the signer. Could be its own epic.
- **Deps:** P2-6.

**P2-8 — BLE endpoint scanner (M3).** Find `BluetoothGatt` service/characteristic UUIDs, scan for read/write/notify patterns. Output into IR alongside HTTP endpoints.
- **Deps:** P2-1 (sibling).

### P-2.5 — Existing integration detection

Sits between Phase 2 and Phase 3. Two-stage:
- **Stage A (post-P1):** package-name match against HA Core component list. Cheap, catches obvious clones.
- **Stage B (post-P2):** API hostname + BLE service UUID match against HA Core + HACS default repo indices.

Both indices are public and cacheable: HA Core integrations at `homeassistant/components/*/manifest.json`, HACS default at `hacs/default`. Cache locally, refresh weekly.

Output verdict: `{found: bool, location: "core"|"hacs"|null, name, repo_url, coverage_estimate: "full"|"partial"|"none"}`. On `full` coverage, pipeline halts with a "skip" recommendation. On `partial`, recommendation is "augment" (generate only missing pieces). On none, proceed normally.
- **Done when:** known Tuya, Shelly, ESPHome APKs trigger the correct verdict.

### Phase 3 — OpenAPI synthesis

**P3-1 — Internal contract IR.** Pydantic models for `Endpoint`, `PayloadSchema`, `AuthScheme`, etc. Decouples extraction from emission.
- **Done when:** IR round-trips to JSON and back losslessly.

**P3-2 — OpenAPI 3.0.3 emitter.** Translate IR → `openapi.yaml`. Type inference rules for primitives, nullable handling, `$ref` for reused schemas.
- **Deps:** P3-1. **Done when:** output validates against the OpenAPI 3.0.3 schema.

**P3-3 — Spec validator.** Run emitted YAML through `openapi-spec-validator` and a swagger linter. Fail loudly on errors.
- **Deps:** P3-2.

### Phase 4 — Standalone async Python SDK

**P4-1 — Jinja template suite for hand-rolled async SDK.** Templates for client class, endpoint methods, pydantic models, exceptions, `__init__.py`. Hand-roll for M1; `openapi-generator-cli` is deferred to P4-5.
- **Deps:** P3-1. **Done when:** renders compilable Python from a fixture IR.

**P4-2 — aiohttp client emitter.** Generates the `ClientSession` wrapper with timeout/retry config, context-manager lifecycle, response error mapping. Must inject the HA-provided session when available (Platinum rule `inject-websession`).
- **Deps:** P4-1.

**P4-3 — Pydantic model emitter.** IR `PayloadSchema` → pydantic v2 models with aliases for `@SerializedName` mappings.
- **Deps:** P4-1.

**P4-4 — Package metadata emitter.** Generates `pyproject.toml`, `README.md`, version pinning. Output is `pip install -e .`-installable.
- **Deps:** P4-1..P4-3. **Done when:** generated SDK installs cleanly in the F-5 sandbox.

**P4-5 — openapi-generator-cli alternative path (M2).** Add as alternative SDK backend for users who want the generator output. Hand-rolled remains default.

**P4-6 — Bleak BLE client template (M3).** Mirror of P4-2 for BLE. Async context-managed `BleakClient`, characteristic R/W/notify wrappers, reconnection logic.
- **Deps:** P2-8, P4-1.

### Phase 5 — HACS component scaffolder

**P5-1 — Blueprint template base.** Fork `ludeeus/integration_blueprint` (or HA's own integration_blueprint cookiecutter) into a Jinja-templatable form. Identify which files are fully templated vs partial-substitution.
- **Done when:** rendering with stub values produces a valid HACS-loadable component.

**P5-2 — `manifest.json` emitter.** Pulls integration metadata, locks the P4-4 SDK as a pip requirement with exact version, sets `quality_scale` from F-7's target, populates `iot_class`.
- **Deps:** P5-1, P4-4, F-7.

**P5-3 — `config_flow.py` emitter.** Generates the user form (host/port/credentials based on extracted auth scheme) and validation call into the SDK's `async_connect()`. Implements `runtime_data` pattern (Platinum rule).
- **Deps:** P5-1, P4-2.

**P5-4 — `DataUpdateCoordinator` emitter.** Wraps SDK polling methods. Default 30s interval, configurable. Uses `_LOGGER` per HA conventions; no exception spam, structured error messages (Platinum rule).
- **Deps:** P5-1, P4-2.

**P5-5 — Entity platform emitters.** Map IR endpoint semantics to `sensor`/`switch`/`button`. M1 heuristic: GET → sensor, POST with boolean → switch, POST with no payload → button. Each entity gets `_attr_has_entity_name = True` and a stable `unique_id` (Bronze rules).
- **Deps:** P5-4.

**P5-6 — `strings.xml` → `strings.json` translator.** Parse Android string resources, filter to user-facing error/state strings, map to HA translation file. Generate `translations/en.json` as well (Gold rule).
- **Deps:** P1-4.

**P5-7 — Auto-discovery extraction (M3).** Parse `NsdManager` usage and multicast/broadcast permissions from P1-4 output, emit `zeroconf`/`dhcp` blocks into `manifest.json` (Gold rule `discovery`).
- **Deps:** P1-4, P5-2.

**P5-8 — Multi-protocol entity mapping (M3).** Extend P5-5 to handle BLE characteristics: notify → sensor, write → switch/button.

---

## 5. Validation tier (V-tier autonomous loop)

The loop's contract: **deterministic checks form the non-negotiable floor; agentic review forms the ceiling. The agent can request fixes but cannot override deterministic failures.**

### V-1 — Eval orchestrator
Receives a generated integration, dispatches to V-2/V-3/V-4 in parallel, aggregates findings into a structured report, calls V-5 with the report. Bounded iteration count. Termination: ship, regenerate (with iteration counter increment), or escalate to human review.
- **Deps:** F-3 (Claude Code orchestration), F-0a, F-0b.

### V-2 — Deterministic static checks
Calls `ha-tooling` MCP: ruff, mypy --strict, hassfest. Returns structured JSON findings.
- **Deps:** F-0a. **Non-negotiable floor.**

### V-3 — HA runtime container test
Spins up HA Core 2026.5.x in Docker via `sandbox` MCP, installs the generated integration, configures with a mock device server returning canned responses, waits for setup to complete or fail, captures full HA log stream. Timeout: 60s of log inactivity = done.
- **Deps:** F-0b, F-5. **Done when:** known-good fixture loads cleanly, known-bad fixture produces parseable failure logs.

### V-4 — Rule review agent
Reads generated files alongside anchor integrations (§6), produces structured findings per quality-scale rule. Categories: idiom adherence, naming, error handling, deprecation, missing features.
- **Deps:** V-4a, V-4b, F-4 (LLM via Claude Code).

### V-4a — Quality rule rubric loader
Pulls canonical rules from HA developer docs, structures them as `{rule_id, tier, check_type, description, example}`. Update mechanism: weekly GitHub Action diffs the upstream rule list.
- **Done when:** rubric is loadable as typed Python objects.

### V-4b — Per-rule check implementations
Many rules are AST-checkable (does the integration use `runtime_data`? does the manifest have `iot_class`?). Build deterministic checkers where possible; reserve agent reasoning for rules requiring semantic understanding.
- **Done when:** ≥60% of platinum rules have deterministic checkers; remainder route to the agent.

### V-5 — Fix router
Takes V-1's aggregated report. For each finding, routes the fix to the specific phase emitter that produced the offending code — not a generic "fix this file" prompt. Lint error in `coordinator.py` → P5-4 emitter with failure context. Wrong schema in OpenAPI → P3-2. Missing endpoint → re-run P2-1 with hint. **This is what makes the loop converge instead of band-aiding output.**
- **Deps:** V-1, all M1 emitters.

### V-6 — Run state persistence
Every pipeline run writes IR, every prompt+response, every agent decision, the eval report, and final output hash to `/runs/{run_id}/`. Required for V-7 and debugging.
- **Deps:** F-3, F-6.

### V-7 — HA log analyzer (autonomous feedback)
Parses captured HA logs from V-3 into structured findings. Categories:
- `setup_failure` — `Setup failed for X`, `ConfigEntryNotReady`, platform load errors
- `async_violation` — "Detected blocking call to..." warnings
- `deprecation` — "X was deprecated in HA Core 20XX.X"
- `schema_error` — config validation failures
- `entity_registry` — unique ID collisions
- `unknown_error` — anything at ERROR/CRITICAL not matched above

Each finding maps to `{severity, category, file_hint, suggested_phase, raw_log_line}`. The `suggested_phase` is what V-5 uses to route the fix.
- **Deps:** V-3. **Done when:** given a log corpus from real failing integrations, V-7 produces correctly-categorized findings on ≥80% of entries.

---

## 6. Anchor integrations

Reference implementations V-4 compares against. Pulled from HA Core at the `config/ha_target.toml` version tag.

| Protocol | Integration | Why |
|---|---|---|
| Local HTTP REST | **AirGradient** | Recent Platinum, open-source partner, clean async client |
| Cloud REST + OAuth | **Teslemetry** | Platinum, complex auth flow |
| TCP socket / custom protocol | **HEOS** | Platinum journey is publicly documented |
| BLE | **SwitchBot** | Bleak-based, characteristic R/W patterns |
| Local push + discovery | **ESPHome** | Canonical zeroconf + push reference |
| Modbus | **Qube Heat Pump** | Industrial protocol reference |

Committed to `fixtures/anchors/` as read-only slices: `manifest.json`, `config_flow.py`, `coordinator.py`, `quality_scale.yaml` per anchor.

---

## 7. Conventions

### Async
- No synchronous I/O inside the event loop. Ever.
- Bluetooth: `async with BleakClient(device) as client:`.
- HTTP: `aiohttp.ClientSession` injected from HA when available.

### Logging
- Module-level `_LOGGER = logging.getLogger(__name__)`.
- No exception spam during retries. Recover silently from transient failures.
- Structured error messages: `_LOGGER.error("Setup failed for %s: %s", entry.entry_id, err)`.
- Generated integrations follow these same rules — V-4 enforces.

### Error handling
- Custom exception hierarchy in each generated SDK. Never raise stdlib exceptions across the API boundary.
- HA-side: `ConfigEntryAuthFailed` for credential issues, `ConfigEntryNotReady` for transient, `UpdateFailed` from coordinators.

### Licensing
- Engine: MIT. SPDX header on every source file.
- Generated integrations: MIT by default, configurable per-generation. SPDX header on every emitted file.

### Typing
- `mypy --strict` clean. No `Any` without justification in a comment.
- Generated SDKs use pydantic v2 models, no untyped dicts.

---

## 8. Iteration budgets

- **Per-issue fix attempts:** 3. LLMs either fix in 1-2 tries or never; >3 wastes tokens.
- **Per-phase regenerations:** 2. If a phase's output is consistently bad, regenerate once with failure context.
- **Total run cap:** 10 fix cycles. After that, halt and emit a `needs-human-review` marker.
- **Per-subagent turn limit:** 25 (`--max-turns`).

Tighten or loosen based on real-run data after the first week.

---

## 9. Milestones

### M1 — Vertical slice (Native Java/Kotlin, HTTP only)
F-0 → F-7 foundation, P1-1..P1-4 (Native branch only), P2-1..P2-3, P-2.5, P3-1..P3-3, P4-1..P4-4, P5-1..P5-6, V-1, V-2, V-5.
**Exit criterion:** pipeline runs end-to-end on a Native Java/Kotlin fixture, produces a HACS integration that loads in a local HA container without crashing on import. Does not need to actually talk to a device yet.

### M2 — Crypto and full validation loop
P2-4..P2-7, P4-5, V-3, V-4, V-4a/b, V-6, V-7.
**Exit criterion:** the loop demonstrably self-corrects. A known-bad emission gets routed to the right phase and fixed within iteration budget.

### M3 — Framework breadth
P1-5, P1-6, P2-8, P4-6, P5-7, P5-8.
**Exit criterion:** Flutter and React Native APKs produce integrations meeting Bronze tier; BLE APKs produce integrations meeting Silver tier.

---

## 10. Open questions (deferred, not blockers)

1. **Evaluation result on `vichhka` MCP** — if it's good, replaces most of Phase 2.
2. **Frida emulator selection** — Android Studio AVD vs Genymotion vs cloud Android. Affects P2-7 build complexity.
3. **Anchor integration update cadence** — manual bump on HA release, or automated.
4. **HACS publication workflow** — does the engine emit a HACS-publishable repo automatically, or do users vendor the output into their own repos?

These don't block M1. Decide as we hit them.
