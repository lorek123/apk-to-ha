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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..ir.models import (
    AuthScheme,
    AuthType,
    ChallengeResponseProfile,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    EntityHint,
    FieldDef,
    FieldKind,
    StateSchema,
    TransportContract,
    TransportType,
)
from . import ble_gatt_profile as gatt_profile
from .app_sources import app_source_files

_LOGGER = logging.getLogger(__name__)

# UUID constant declarations:  [Modifiers] UUID CONST_NAME = UUID.fromString("...");
# Tolerates multi-line formatting (modifiers on one line, UUID.fromString on next).
_UUID_CONST_RE = re.compile(
    r"(?:(?:public|private|protected|static|final)\s+)*"
    r'UUID\s+(\w+)\s*=\s*UUID\.fromString\s*\(\s*"([0-9a-fA-F-]{36})"\s*\)'
)

# Inline UUID.fromString() without a named assignment
_UUID_INLINE_RE = re.compile(r'UUID\.fromString\s*\(\s*"([0-9a-fA-F-]{36})"\s*\)')

# Variable assignment from getCharacteristic:
#   SomeType varName = anything.getCharacteristic(CONST_NAME)
# The argument is a constant or its Kotlin getter: BleConstants.INSTANCE.getFAN_UUID().
_VAR_FROM_GETCHAR_RE = re.compile(
    r"(?:\w+\s+)?(\w+)\s*=\s*[^;]*?getCharacteristic\s*\(\s*([\w.$]+?)(?:\(\))?\s*\)"
)
_GETTER_REF = re.compile(r"(?:[\w$]+\.)*(?:get)?(\w+)$")
# A method declaration (bindings don't cross them): "    public final void f(int x) {"
_METHOD_START = re.compile(
    r"^[ \t]+(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)+"
    r"[\w.<>\[\], ?]+\s+[\w$]+\s*\([^)]*\)\s*(?:throws\s+[\w., ]+)?\{",
    re.MULTILINE,
)

# Patterns that capture a simple variable/const name as the first arg:
#   gatt.writeCharacteristic(varName)  or  gatt.writeCharacteristic(CONST_NAME, ...)
_WRITE_VAR_RE = re.compile(r"writeCharacteristic\s*\(\s*(\w+)\s*[,)]")
_READ_VAR_RE = re.compile(r"readCharacteristic\s*\(\s*(\w+)\s*[,)]")
_NOTIFY_VAR_RE = re.compile(r"setCharacteristicNotification\s*\(\s*(\w+)\s*[,)]")
# Any GATT access call and its full argument list (for wrapper / getter forms).
_GATT_CALL_RE = re.compile(
    r"\b(writeCharacteristic|readCharacteristic|setCharacteristicNotification)\s*\(([^;]*)\)"
)
_GATT_CALL_KIND = {
    "writeCharacteristic": "write",
    "readCharacteristic": "read",
    "setCharacteristicNotification": "notify",
}

# Inline patterns that capture through nested parens:
#   gatt.writeCharacteristic(anything.getCharacteristic(CONST) ...)
_WRITE_INLINE_RE = re.compile(r"writeCharacteristic\s*\([^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)")
_READ_INLINE_RE = re.compile(r"readCharacteristic\s*\([^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)")
_NOTIFY_INLINE_RE = re.compile(
    r"setCharacteristicNotification\s*\([^;]*?getCharacteristic\s*\(\s*(\w+)\s*\)"
)

_HAS_BLE_RE = re.compile(r"BluetoothGatt|BluetoothLeScanner|BleManager|BleClient")

# Prefixes/suffixes stripped from UUID constant names when deriving cmd names
_STRIP_PREFIX_RE = re.compile(r"^(?:UUID_|CHAR(?:ACTERISTIC)?_|BLE_)", re.I)
_STRIP_SUFFIX_RE = re.compile(r"_(?:UUID|CHAR(?:ACTERISTIC)?)$", re.I)


@dataclass
class _CharInfo:
    const_name: str | None
    uuid: str
    access: set[str] = field(default_factory=set)  # "write" | "read" | "notify"
    source_class: str | None = None


class BLEScanner:
    """Extract BLE protocol IR from a decompiled APK output directory."""

    def __init__(self, apk_out_dir: Path) -> None:
        self._root = apk_out_dir
        self.extra: dict[str, Any] = {}

    def scan(
        self,
        package_name: str,
    ) -> tuple[
        TransportContract,
        DiscoveryMechanism,
        AuthScheme,
        StateSchema,
        list[Endpoint],
        list[Endpoint],
    ]:
        sources = self._root / "sources"
        java_files = (
            app_source_files(sources, package_name)
            if sources.exists()
            else list(self._root.rglob("*.java"))
        )
        texts: dict[str, str] = {}
        named_scans: list[str] = []  # device-list code (may use classic discovery)
        for path in java_files:
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if _HAS_BLE_RE.search(text) or _UUID_INLINE_RE.search(text):
                texts[path.stem] = text
            if "getName()" in text:
                named_scans.append(text)
        if not texts:
            return _defaults()

        # Pass 1: UUID constants from every file (a Kotlin companion object defines
        # them in one class; other classes use them).
        chars: list[_CharInfo] = []
        service_uuids: list[str] = []
        service_names: dict[str, str] = {}
        char_names: dict[str, str] = {}
        all_text = "\n".join(texts.values())
        for class_name, text in texts.items():
            for const_name, uuid in _named_uuids(text).items():
                if _is_service(const_name, all_text):
                    service_uuids.append(uuid)
                    service_names[uuid] = const_name
                else:
                    char_names[const_name] = uuid
                    chars.append(_CharInfo(const_name, uuid, set(), class_name))

        # Pass 2: how each characteristic is used, across all files.
        access_map = _build_access_map(all_text, char_names)
        # Pass 3: the values the app writes and how it decodes reads.
        profiles = gatt_profile.analyze(list(texts.values()), char_names)
        for ch in chars:
            ch.access = access_map.get(ch.uuid, {"read"})  # default: assume readable
            if ch.uuid in profiles and profiles[ch.uuid].decode:
                ch.access.add("read")  # the app's read/notify handler decodes it
        chars = _dedup(chars)

        if not chars:
            return _defaults()

        _LOGGER.info(
            "ble_scanner: %d characteristics, %d services found",
            len(chars),
            len(service_uuids),
        )
        self.extra["ble_service_uuids"] = list(dict.fromkeys(service_uuids))
        self.extra["ble_service_names"] = service_names

        # cmd → uuid mapping consumed by the BLE client template emitter
        self.extra["ble_char_uuids"] = {
            _uuid_to_cmd(ch.const_name, ch.uuid): ch.uuid for ch in chars
        }
        # cmd → sorted access list for template rendering
        self.extra["ble_char_access"] = {
            _uuid_to_cmd(ch.const_name, ch.uuid): sorted(ch.access) for ch in chars
        }

        self.extra["ble_gatt"] = {
            _uuid_to_cmd(ch.const_name, ch.uuid): asdict(profiles[ch.uuid])
            for ch in chars
            if ch.uuid in profiles
        }

        commands: list[Endpoint] = []
        events: list[Endpoint] = []
        for ch in chars:
            ep = _char_to_endpoint(ch, profiles.get(ch.uuid))
            (commands if ep.direction == Direction.TO_DEVICE else events).append(ep)

        transport = TransportContract(type=TransportType.BLE)
        local_name = gatt_profile.local_name_filter(named_scans)
        discovery = DiscoveryMechanism(
            type=DiscoveryType.BLUETOOTH if local_name or service_uuids else DiscoveryType.NONE,
            local_name=local_name,
        )
        auth = _detect_challenge_auth(commands, events)
        state = StateSchema()
        return transport, discovery, auth, state, commands, events


# ── file-level extraction ──────────────────────────────────────────────────────


_CHALLENGE_NAME = re.compile(r"nonce|challenge", re.IGNORECASE)
_PROOF_NAME = re.compile(r"auth|sign|proof|response", re.IGNORECASE)


def _detect_challenge_auth(commands: list[Endpoint], events: list[Endpoint]) -> AuthScheme:
    """A readable nonce/challenge plus a writable auth/signature → challenge-response."""
    challenge = next((e.cmd for e in events if _CHALLENGE_NAME.search(e.cmd)), None)
    proof = next(
        (
            c.cmd
            for c in commands
            if _PROOF_NAME.search(c.cmd) and not _CHALLENGE_NAME.search(c.cmd)
        ),
        None,
    )
    if challenge is None or proof is None:
        return AuthScheme(type=AuthType.NONE)
    return AuthScheme(
        type=AuthType.CHALLENGE_RESPONSE,
        handshake_cmd=proof,
        description=f"Read '{challenge}', write the signed response to '{proof}'",
        # Roles only; the pipeline completes it once crypto and traces are known.
        challenge=ChallengeResponseProfile(challenge=challenge, proof=proof),
    )


def _named_uuids(text: str) -> dict[str, str]:
    """const_name → uuid for UUID constants in *text*.

    Kotlin companion objects decompile to a temporary plus an assignment:
    ``UUID uuidFromString8 = UUID.fromString("…"); ACTION_UUID = uuidFromString8;``
    — the constant's real name is the assignment target.
    """
    named: dict[str, str] = {}
    for m in _UUID_CONST_RE.finditer(text):
        name = m.group(1)
        alias = re.search(rf"\b([A-Za-z_]\w*)\s*=\s*{re.escape(name)}\s*;", text[m.end() :])
        named[alias.group(1) if alias else name] = m.group(2).lower()
    return named


def _scan_file(text: str, class_name: str) -> tuple[list[_CharInfo], list[str]]:
    """Return (characteristics, service_uuids) found in one Java file."""
    # Collect named UUID constants: const_name → uuid
    named = _named_uuids(text)
    if not named:
        return [], []

    # Classify each named UUID as service or characteristic
    service_uuids: list[str] = []
    char_names: dict[str, str] = {}  # const_name → uuid (for characteristics only)
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
        access = access_map.get(uuid, {"read"})  # default: assume readable
        chars.append(
            _CharInfo(const_name=const_name, uuid=uuid, access=access, source_class=class_name)
        )

    return chars, service_uuids


def _is_service(const_name: str, text: str) -> bool:
    """Return True if this UUID constant is used as a GATT service (not characteristic)."""
    if re.search(r"SERVICE", const_name, re.I):
        return True
    # Only a service if it appears directly as the argument to getService(...)
    if re.search(rf"getService\s*\(\s*{re.escape(const_name)}\s*\)", text):
        return True
    return False


def _build_access_map(text: str, char_names: dict[str, str]) -> dict[str, set[str]]:
    """Return {uuid → access_set} using statement-level gatt call analysis.

    Two-level strategy:
    1. var = getCharacteristic(CONST_NAME) → bind var to uuid
    2. gatt.writeCharacteristic(var|CONST) → add "write" for that uuid
    """
    # Step 1: bind variable names to UUIDs, by position. Decompiled code reuses the
    # same local name ("characteristic") in every method, so a use resolves to the
    # nearest binding before it, not to the last one in the file.
    bindings: dict[str, list[tuple[int, str]]] = {}
    for m in _VAR_FROM_GETCHAR_RE.finditer(text):
        uuid = _ref_uuid(m.group(2), char_names)
        if uuid:
            bindings.setdefault(m.group(1), []).append((m.start(), uuid))

    access_map: dict[str, set[str]] = {}

    method_starts = [m.start() for m in _METHOD_START.finditer(text)]

    def _resolve_name(name: str, pos: int) -> str | None:
        """Resolve a simple identifier (const or variable) to a UUID at *pos*."""
        if name in char_names:
            return char_names[name]
        method = max((s for s in method_starts if s < pos), default=0)
        before = [uuid for start, uuid in bindings.get(name, []) if method <= start < pos]
        return before[-1] if before else None

    def _record_var(pattern: re.Pattern[str], access_kind: str) -> None:
        """Handle write/read/notify(varName, ...) — simple identifier first arg."""
        for m in pattern.finditer(text):
            uuid = _resolve_name(m.group(1), m.start())
            if uuid:
                access_map.setdefault(uuid, set()).add(access_kind)

    def _record_inline(pattern: re.Pattern[str], access_kind: str) -> None:
        """Handle write/read/notify(x.getCharacteristic(CONST)) — inline call."""
        for m in pattern.finditer(text):
            uuid = _resolve_name(m.group(1), m.start())
            if uuid:
                access_map.setdefault(uuid, set()).add(access_kind)

    _record_var(_WRITE_VAR_RE, "write")
    _record_var(_READ_VAR_RE, "read")
    _record_var(_NOTIFY_VAR_RE, "notify")
    _record_inline(_WRITE_INLINE_RE, "write")
    _record_inline(_READ_INLINE_RE, "read")
    _record_inline(_NOTIFY_INLINE_RE, "notify")

    # Wrappers and Kotlin getters: bleManager.writeCharacteristic(gatt,
    # BleManager.INSTANCE.getACTION_UUID(), bytes) — the characteristic is any
    # argument that names a known constant (directly or via its getter).
    for m in _GATT_CALL_RE.finditer(text):
        kind = _GATT_CALL_KIND[m.group(1)]
        for const_name, uuid in char_names.items():
            if re.search(rf"\b(?:get)?{re.escape(const_name)}\b", m.group(2)):
                access_map.setdefault(uuid, set()).add(kind)

    return access_map


def _ref_uuid(ref: str, char_names: dict[str, str]) -> str | None:
    """UUID for a constant reference: CONST, Owner.CONST or Owner.INSTANCE.getCONST."""
    if ref in char_names:
        return char_names[ref]
    m = _GETTER_REF.search(ref)
    if m and m.group(1) in char_names:
        return char_names[m.group(1)]
    return None


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


def _char_to_endpoint(ch: _CharInfo, profile: gatt_profile.CharProfile | None = None) -> Endpoint:
    cmd = _uuid_to_cmd(ch.const_name, ch.uuid)
    # A one-byte writer with known values: the parameter the command takes.
    fields = (
        [FieldDef(name="value", kind=FieldKind.INTEGER, enum_values=list(profile.values))]
        if profile and profile.write_encoding and profile.values
        else []
    )
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
        request_fields=fields,
        source_class=ch.source_class,
        entity_hint=hint,
        confidence=0.7,
    )


def _uuid_to_cmd(const_name: str | None, uuid: str) -> str:
    if const_name:
        name = _STRIP_PREFIX_RE.sub("", const_name)
        while _STRIP_SUFFIX_RE.search(name):  # FAN_SPEED_CHARACTERISTIC_UUID → FAN_SPEED
            name = _STRIP_SUFFIX_RE.sub("", name)
        if not name:
            name = const_name
        parts = re.split(r"[_-]", name.lower())
        return parts[0] + "".join(p.capitalize() for p in parts[1:])
    suffix = uuid.replace("-", "")[-8:]
    return f"char{suffix}"


# ── defaults ───────────────────────────────────────────────────────────────────


def _defaults() -> tuple[
    TransportContract, DiscoveryMechanism, AuthScheme, StateSchema, list[Any], list[Any]
]:
    return (
        TransportContract(type=TransportType.BLE),
        DiscoveryMechanism(type=DiscoveryType.NONE),
        AuthScheme(type=AuthType.NONE),
        StateSchema(),
        [],
        [],
    )
