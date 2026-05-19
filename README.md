# HACS Integration Engine

> Reverse-engineer an Android `.apk` and emit a Platinum-tier Home Assistant integration.

An autonomous pipeline that ingests a device's Android companion app, statically extracts its communication contract (HTTP REST, BLE, TCP, or local discovery), generates a standalone async Python SDK, and scaffolds a complete HACS integration meeting Home Assistant's [Platinum quality scale](https://www.home-assistant.io/docs/quality_scale/).

## How it works

```
target.apk
    ↓
Framework classification  →  Existing-integration check  →  bail out if duplicate
    ↓
Static contract extraction (Retrofit / OkHttp / BLE / sockets)
    ↓
OpenAPI 3.0.3 spec
    ↓
Standalone async Python SDK (aiohttp / bleak)
    ↓
HACS integration scaffold (config_flow, coordinator, entities)
    ↓
Autonomous validation loop  →  hassfest + HA container test + rule review  →  self-correct or ship
```

The validation loop is the differentiator. Generated integrations are loaded into a real Home Assistant container, their startup logs are parsed for errors and deprecation warnings, and findings are routed back to the specific generation phase that produced the offending code. No human in the feedback loop.

## Status

Pre-M1. Foundation tier in progress. See [`SPECIFICATION.md`](./SPECIFICATION.md) for the full ticket roster and acceptance criteria.

## Quick start

### Devcontainer (recommended)

Open this repo in VS Code or Cursor with the Dev Containers extension. Accept the rebuild prompt. Everything is pre-installed at pinned versions: Python 3.14, JADX with the `jadx-ai-mcp` plugin, Docker-in-Docker for the HA container test, all MCP servers.

```bash
./scripts/setup.sh smoke   # end-to-end smoke test against the demo fixture
```

### Host machine fallback

```bash
./scripts/setup.sh         # detects OS, installs deps via brew/apt
./scripts/setup.sh --check # verify-only mode
```

Tested on Ubuntu 24.04 and macOS 14+. Windows users should use the devcontainer.

## What this is not

This engine is for analyzing device communication protocols in apps you have a legitimate reason to study — your own devices, vendors you've signed an NDA with, abandoned products you're keeping alive, etc. It is **not** for circumventing license enforcement, anti-tamper, or DRM, and it will refuse to operate on apps in those categories where detectable.

The fixture corpus distributes derivative analysis snippets only — never APK binaries.

## License

MIT. See [`LICENSE`](./LICENSE). Compatible with future upstreaming into HA Core (Apache 2.0).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). All contributions are inbound under MIT.
