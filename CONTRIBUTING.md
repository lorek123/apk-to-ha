# Contributing

Thanks for the interest. The engine is still in foundation-tier work — most surfaces are unstable. Check `SPECIFICATION.md` §9 for milestone status before starting non-trivial work.

## Licensing

All contributions are inbound under the MIT license. By submitting a pull request you agree to license your contribution under MIT and that you have the right to do so.

Every source file you add must include `# SPDX-License-Identifier: MIT` (or the equivalent for that file type) as its first non-shebang line.

## Development setup

Use the devcontainer if at all possible. See `README.md` for setup. The host-machine path via `scripts/setup.sh` works but is harder to keep reproducible.

## Coding conventions

See `SPECIFICATION.md` §7. Highlights:

- Async-only inside event loop contexts.
- `mypy --strict` clean.
- `ruff` for formatting and linting; defaults from `pyproject.toml`.
- Logging via module-level `_LOGGER = logging.getLogger(__name__)`. No `print()`.

## Pull requests

- One ticket per PR. Reference the ticket ID in the title: `[P5-3] config_flow emitter handles host+port form`.
- Include tests. If the work touches an emitter, include a fixture-level test that runs the emitter and validates the output.
- The CI must be green. No exceptions, no "I'll fix it later".

## Filing issues

Use the issue templates when they exist. For now, include:

- The ticket ID(s) the issue relates to.
- Reproducer steps. If a generation failed, include the `/runs/{run_id}/` directory contents (sanitize first).
- Your `config/ha_target.toml` if relevant.

## Code of conduct

Be excellent to each other. The Home Assistant community guidelines apply here by default.
