# SPDX-License-Identifier: MIT
"""P2-8 — BLE/GATT endpoint scanner.

Walks decompiled Java source and extracts:
  - BluetoothGattCharacteristic UUIDs → Endpoint objects
  - Service UUIDs → stored in extra["ble_service_uuids"]
  - Access patterns per UUID: write → TO_DEVICE, read/notify → FROM_DEVICE

Uses a two-level matching strategy:
  1. Variable-to-UUID binding: `var = ...getCharacteristic(UUID_CONST)`
  2. Gatt call parsing: `gatt.writeCharacteristic(var)` or inline getCharacteristic

Bronze-tier quality: covers common Bluetooth SDK patterns. Dynamic oracle
(P2-7) upgrades confidence in M3.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    EntityHint,
    StateSchema,
    TransportContract,
    TransportType,
)

_LOGGER = logging.getLogger(__name__)

# UUID constant declarations:  [Modifiers] UUID CONST_NAME = UUID.fromString("...");
# Tolerates multi-line formatting (modifiers on one line, UUID.fromString on next).
_UUID_CONST_RE = re.compile(
    r'(?:(?:public|private|protected|static|final)\s+)*'
    r'UUID\s+(\w+)\s*=\s*UUID\.fromString\s*\(\s*"([0-9a-fA-F-]{36})"\s*\)'
)

# Inline UUID.fromString() without a named assignment
_UUID_INLINE_RE = re.compile(r'UUID\.fromString\s*\(\s*"([0-9a-fA-F-]{36})"\s*\)')

# Variable assignment from getCharacteristic:
#   SomeType varName = anything.getCharacteristic(CONST_NAME)
_VAR_FROM_GETCHAR_RE = re.compile(
    r'(?:\w+\s+)?(\w+)\s*=\s*[^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)'
)

# Patterns that capture a simple variable/const name as the first arg:
#   gatt.writeCharacteristic(varName)  or  gatt.writeCharacteristic(CONST_NAME, ...)
_WRITE_VAR_RE = re.compile(r'writeCharacteristic\s*\(\s*(\w+)\s*[,)]')
_READ_VAR_RE = re.compile(r'readCharacteristic\s*\(\s*(\w+)\s*[,)]')
_NOTIFY_VAR_RE = re.compile(r'setCharacteristicNotification\s*\(\s*(\w+)\s*[,)]')

# Inline patterns that capture through nested parens:
#   gatt.writeCharacteristic(anything.getCharacteristic(CONST) ...)
_WRITE_INLINE_RE = re.compile(
    r'writeCharacteristic\s*\([^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)'
)
_READ_INLINE_RE = re.compile(
    r'readCharacteristic\s*\([^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)'
)
_NOTIFY_INLINE_RE = re.compile(
    r'setCharacteristicNotification\s*\([^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)'
)

_HAS_BLE_RE = re.compile(r'BluetoothGatt|BluetoothLeScanner|BleManager|BleClient')

# Prefixes/suffixes stripped from UUID constant names when deriving cmd names
_STRIP_PREFIX_RE = re.compile(r'^(?:UUID_|CHAR(?:ACTERISTIC)?_|BLE_)', re.I)
_STRIP_SUFFIX_RE = re.compile(r'_(?:UUID|CHAR(?:ACTERISTIC)?)$', re.I)


@dataclass
class _CharInfo:
    const_name: str | None
    uuid: str
    access: set[str] = field(default_factory=set)   # "write" | "read" | "notify"
    source_class: str | None = None


class BLEScanner:
    """Extract BLE protocol IR from a decompiled APK output directory."""

    def __init__(self, apk_out_dir: Path) -> None:
        self._root = apk_out_dir
        self.extra: dict[str, Any] = {}

    def scan(
        self, package_name: str,
    ) -> tuple[TransportContract, DiscoveryMechanism, AuthScheme, StateSchema, list[Endpoint], list[Endpoint]]:
        java_files = list(self._root.rglob("*.java"))
        if not java_files:
            return _defaults()

        chars: list[_CharInfo] = []
        service_uuids: list[str] = []

        for path in java_files:
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if not _HAS_BLE_RE.search(text):
                continue

            file_chars, file_services = _scan_file(text, path.stem)
            chars.extend(file_chars)
            service_uuids.extend(file_services)

        chars = _dedup(chars)

        if not chars:
            return _defaults()

        _LOGGER.info(
            "ble_scanner: %d characteristics, %d services found",
            len(chars), len(service_uuids),
        )
        self.extra["ble_service_uuids"] = list(dict.fromkeys(service_uuids))

        commands: list[Endpoint] = []
        events: list[Endpoint] = []
        for ch in chars:
            ep = _char_to_endpoint(ch)
            (commands if ep.direction == Direction.TO_DEVICE else events).append(ep)

        transport = TransportContract(type=TransportType.BLE)
        discovery = DiscoveryMechanism(type=DiscoveryType.NONE)
        auth = AuthScheme(type=AuthType.NONE)
        state = StateSchema()
        return transport, discovery, auth, state, commands, events


# ── file-level extraction ──────────────────────────────────────────────────────

def _scan_file(text: str, class_name: str) -> tuple[list[_CharInfo], list[str]]:
    """Return (characteristics, service_uuids) found in one Java file."""
    # Collect named UUID constants: const_name → uuid
    named: dict[str, str] = {}
    for m in _UUID_CONST_RE.finditer(text):
        named[m.group(1)] = m.group(2).lower()

    if not named:
        return [], []

    # Classify each named UUID as service or characteristic
    service_uuids: list[str] = []
    char_names: dict[str, str] = {}    # const_name → uuid (for characteristics only)
    for const_name, uuid in named.items():
        if _is_service(const_name, text):
            service_uuids.append(uuid)
        else:
            char_names[const_name] = uuid

    if not char_names:
        return [], service_uuids

    # Build access map for characteristics via statement-level analysis
    access_map = _build_access_map(text, char_names)

    chars: list[_CharInfo] = []
    for const_name, uuid in char_names.items():
        access = access_map.get(uuid, {"read"})   # default: assume readable
        chars.append(_CharInfo(const_name=const_name, uuid=uuid, access=access, source_class=class_name))

    return chars, service_uuids


def _is_service(const_name: str, text: str) -> bool:
    """Return True if this UUID constant is used as a GATT service (not characteristic)."""
    if re.search(r'SERVICE', const_name, re.I):
        return True
    # Only a service if it appears directly as the argument to getService(...)
    if re.search(rf'getService\s*\(\s*{re.escape(const_name)}\s*\)', text):
        return True
    return False


def _build_access_map(text: str, char_names: dict[str, str]) -> dict[str, set[str]]:
    """Return {uuid → access_set} using statement-level gatt call analysis.

    Two-level strategy:
    1. var = getCharacteristic(CONST_NAME) → bind var to uuid
    2. gatt.writeCharacteristic(var|CONST) → add "write" for that uuid
    """
    # Step 1: bind variable names to UUIDs
    var_to_uuid: dict[str, str] = {}
    for m in _VAR_FROM_GETCHAR_RE.finditer(text):
        var_name = m.group(1)
        ref = m.group(2)
        if ref in char_names:
            var_to_uuid[var_name] = char_names[ref]

    access_map: dict[str, set[str]] = {}

    def _resolve_name(name: str) -> str | None:
        """Resolve a simple identifier (const or variable) to a UUID."""
        if name in char_names:
            return char_names[name]
        return var_to_uuid.get(name)

    def _record_var(pattern: re.Pattern[str], access_kind: str) -> None:
        """Handle write/read/notify(varName, ...) — simple identifier first arg."""
        for m in pattern.finditer(text):
            uuid = _resolve_name(m.group(1))
            if uuid:
                access_map.setdefault(uuid, set()).add(access_kind)

    def _record_inline(pattern: re.Pattern[str], access_kind: str) -> None:
        """Handle write/read/notify(x.getCharacteristic(CONST)) — inline call."""
        for m in pattern.finditer(text):
            uuid = _resolve_name(m.group(1))
            if uuid:
                access_map.setdefault(uuid, set()).add(access_kind)

    _record_var(_WRITE_VAR_RE, "write")
    _record_var(_READ_VAR_RE, "read")
    _record_var(_NOTIFY_VAR_RE, "notify")
    _record_inline(_WRITE_INLINE_RE, "write")
    _record_inline(_READ_INLINE_RE, "read")
    _record_inline(_NOTIFY_INLINE_RE, "notify")

    return access_map


# ── deduplication ──────────────────────────────────────────────────────────────

def _dedup(chars: list[_CharInfo]) -> list[_CharInfo]:
    merged: dict[str, _CharInfo] = {}
    for ch in chars:
        if ch.uuid in merged:
            merged[ch.uuid].access |= ch.access
            if merged[ch.uuid].const_name is None and ch.const_name:
                merged[ch.uuid].const_name = ch.const_name
        else:
            merged[ch.uuid] = _CharInfo(
                const_name=ch.const_name,
                uuid=ch.uuid,
                access=set(ch.access),
                source_class=ch.source_class,
            )
    return list(merged.values())


# ── endpoint construction ──────────────────────────────────────────────────────

def _char_to_endpoint(ch: _CharInfo) -> Endpoint:
    cmd = _uuid_to_cmd(ch.const_name, ch.uuid)
    is_write = "write" in ch.access
    is_notify = "notify" in ch.access
    is_read = "read" in ch.access

    direction = Direction.TO_DEVICE if is_write else Direction.FROM_DEVICE

    if is_notify:
        hint = EntityHint.SENSOR
    elif is_write and not is_read:
        hint = EntityHint.SWITCH
    elif is_read and not is_write:
        hint = EntityHint.SENSOR
    else:
        hint = None

    return Endpoint(
        cmd=cmd,
        transport=TransportType.BLE,
        direction=direction,
        description=f"BLE characteristic {ch.uuid} ({', '.join(sorted(ch.access))})",
        source_class=ch.source_class,
        entity_hint=hint,
        confidence=0.7,
    )


def _uuid_to_cmd(const_name: str | None, uuid: str) -> str:
    if const_name:
        name = _STRIP_PREFIX_RE.sub("", const_name)
        name = _STRIP_SUFFIX_RE.sub("", name)
        if not name:
            name = const_name
        parts = re.split(r"[_-]", name.lower())
        return parts[0] + "".join(p.capitalize() for p in parts[1:])
    suffix = uuid.replace("-", "")[-8:]
    return f"char{suffix}"


# ── defaults ───────────────────────────────────────────────────────────────────

def _defaults() -> tuple[TransportContract, DiscoveryMechanism, AuthScheme, StateSchema, list, list]:
    return (
        TransportContract(type=TransportType.BLE),
        DiscoveryMechanism(type=DiscoveryType.NONE),
        AuthScheme(type=AuthType.NONE),
        StateSchema(),
        [],
        [],
    )

