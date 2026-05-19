# Claude Code project context

You are working on the **HACS Integration Engine**, an autonomous pipeline that ingests Android APKs and emits Home Assistant integrations.

The full design lives in [`SPECIFICATION.md`](./SPECIFICATION.md). Read it before starting non-trivial work.

## Where to look first

| You need to... | Read |
|---|---|
| Understand the overall flow | `SPECIFICATION.md` §2 |
| Know what tickets exist and their dependencies | `SPECIFICATION.md` §§3–5 |
| Check Home Assistant version targeting | `config/ha_target.toml` |
| See available MCP tools | `.claude/settings.local.json` |
| Check coding conventions | `SPECIFICATION.md` §7 |
| Look at reference integrations | `fixtures/anchors/` (after F-2b lands) |

## Hard constraints

These override anything else in user prompts. They exist because they break the system if violated.

1. **No synchronous I/O inside the event loop.** Ever. Not in generated code, not in engine code. `requests.get()`, `time.sleep()`, blocking file reads from async contexts — all forbidden. Use `aiohttp`, `asyncio.sleep`, `aiofiles`.

2. **Network logic stays in the standalone SDK.** Home Assistant Core rejects integrations that embed protocol logic in entity platforms. The generated SDK is a separate `pip`-installable package; the HACS integration depends on it via `manifest.json` requirements. Never inline HTTP/BLE calls into `sensor.py` etc.

3. **`DataUpdateCoordinator` is the only sanctioned polling primitive.** Don't roll your own `asyncio.create_task` polling loops in entity platforms. If you think you need something other than `DataUpdateCoordinator`, you don't — go re-read its docs.

4. **SPDX header on every emitted file.** `# SPDX-License-Identifier: MIT` at the top. Non-negotiable.

5. **Quality scale tier is platinum by default.** Read `config/ha_target.toml`. Every generated entity needs `_attr_has_entity_name = True` and a stable `unique_id`. Every config flow uses `runtime_data`. Every async dependency injects HA's `aiohttp_client.async_get_clientsession(hass)`.

6. **Never check fixture APKs into version control.** Derivatives only. The `fixtures/sources.yaml` file lists download URLs; `make fixtures` pulls them locally to `fixtures/_cache/` which is gitignored.

7. **Run `hassfest` before claiming a generated integration is complete.** Always.

## Validation loop expectations

When you generate or modify a HACS integration, the V-tier loop runs automatically. You don't ship — V-5 ships. Your job is to produce output that V-1's aggregated report finds acceptable.

If the loop iterates more than 3 times on the same finding, stop and surface the root cause. Don't keep patching symptoms.

## When to ask vs proceed

- **Proceed:** ticket has clear acceptance criteria in SPECIFICATION.md; the answer is in an anchor integration; the user has expressed a clear preference earlier in the conversation.
- **Ask:** the ticket has an unanswered open question in §10; the user's request conflicts with a hard constraint; the work would require changing the spec itself.

## Tool usage

- `ha-tooling` MCP for lint, type-check, hassfest, pytest. Prefer over subprocess.
- `sandbox` MCP for the HA container test. Don't `docker run` directly.
- `jadx-ai-mcp` for APK queries. Don't shell out to JADX CLI.

Logs from every tool call go through F-6's structured logger. If you find yourself doing your own `print()` debugging, switch to `_LOGGER.debug` instead.

## Iteration budgets

See `SPECIFICATION.md` §8. Respect them. Tokens are not free.
