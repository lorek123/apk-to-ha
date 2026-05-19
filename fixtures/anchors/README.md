# Anchor integrations

Read-only slices of canonical HA Core integrations that V-4 compares generated output against.

Populated by a script (TBD) that pulls from HA Core at the tag declared in `config/ha_target.toml [anchors] ref`. Refreshed when that tag bumps.

Each anchor contains the minimum useful subset:
- `manifest.json`
- `config_flow.py`
- `coordinator.py`
- `quality_scale.yaml`
- One representative entity platform (`sensor.py`, `switch.py`, etc.)

See `SPECIFICATION.md` §6 for the current anchor list and rationale.
