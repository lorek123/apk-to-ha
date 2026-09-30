# SPDX-License-Identifier: MIT
"""P2-8b — What a plain (unauthenticated) GATT app writes and how it reads.

The BLE scanner knows *which* characteristics are read and written; this module
works out the values, from the app's own code:

  writers   ``void writeFanSpeed(int value) { … setValue(new byte[]{(byte) value}) …
            writeCharacteristic(characteristic) }`` → one unsigned byte, and the
            integer literals its call sites pass (``writeFanSpeed(4)``) → the values
            the app actually sends
  decoding  the app's notification/read handler, one branch per characteristic
            (``if (Intrinsics.areEqual(uuid, …getFAN_SPEED_UUID())) { fanSpeed =
            value[0]; … }``) → int8 / int16le / utf8 / bool
  discovery the scan filter on the advertised name (``name.contains("FirePit")``)

Anything not recognised is left out: an undecoded characteristic doesn't become
a sensor, and a write without a known value set doesn't become a control.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

_METHOD = re.compile(
    r"^[ \t]+(?:(?:public|private|protected|static|final|synchronized)\s+)+"
    r"[\w.<>\[\], ?]+\s+([\w$]+)\s*\(([^)]*)\)\s*(?:throws\s+[\w., ]+)?\{",
    re.MULTILINE,
)
_GETCHAR = re.compile(r"getCharacteristic\s*\(\s*([\w.$]+?)(?:\(\))?\s*\)")
# byte[] bArr = {(byte) value};  /  new byte[]{(byte) value}
_ONE_BYTE = re.compile(r"\{\s*\(byte\)\s*(\w+)\s*\}")
_SET_VALUE = re.compile(r"\.setValue\s*\(")
_WRITE = re.compile(r"writeCharacteristic\s*\(")
_INT_PARAM = re.compile(r"\b(?:int|short|byte)\s+(\w+)")
# Branch of a read/notify handler: Intrinsics.areEqual(uuid, X.INSTANCE.getFAN_UUID())
_BRANCH = re.compile(
    r"(?:Intrinsics\.areEqual\(\s*\w+\s*,\s*([\w.$]+?)(?:\(\))?\s*\)"
    r"|\b\w+\.equals\(\s*([\w.$]+?)(?:\(\))?\s*\))"
)
_BRANCH_WINDOW = 1500
_DECODERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"bytesTo(?:Short|Int16)LE\(|LITTLE_ENDIAN\)\.getShort"), "int16le"),
    (re.compile(r"FORMAT_UINT16"), "uint16le"),
    (re.compile(r"FORMAT_SINT16"), "int16le"),
    (re.compile(r"FORMAT_UINT8"), "uint8"),
    (re.compile(r"FORMAT_SINT8"), "int8"),
    (re.compile(r"new String\(\s*\w+\s*,|getStringValue\("), "utf8"),
]
_FIRST_BYTE = re.compile(r"(?:(\w+)\s*=\s*)?\b\w+\[0\]")
# name.contains("FirePit") / StringsKt.contains$default(name, "FirePit", …) / startsWith
_NAME_FILTER = re.compile(
    r"(?:contains(?:\$default)?|startsWith(?:\$default)?)\(\s*"
    r'(?:\(CharSequence\)\s*)?\w+\s*,\s*(?:\(CharSequence\)\s*)?"([^"]{3,})"'
    r'|\.(?:contains|startsWith)\(\s*"([^"]{3,})"'
)
_NAME_WINDOW = 800


@dataclass
class CharProfile:
    decode: str | None = None  # int8 | uint8 | int16le | uint16le | utf8 | bool
    writer: str | None = None  # the app method that writes it
    write_encoding: str | None = None  # uint8 (one byte from an int parameter)
    values: list[int] = field(default_factory=list)  # literals the app writes


def analyze(texts: list[str], char_names: dict[str, str]) -> dict[str, CharProfile]:
    """uuid → CharProfile, for the characteristics named in *char_names* (const → uuid)."""
    profiles: dict[str, CharProfile] = {}
    all_text = "\n".join(texts)

    def ref_uuid(ref: str) -> str | None:
        last = re.sub(r"^get", "", ref.split(".")[-1])
        return char_names.get(ref) or char_names.get(last)

    for text in texts:
        methods = list(_METHOD.finditer(text))
        bounds = [m.start() for m in methods] + [len(text)]
        for m, end in zip(methods, bounds[1:], strict=True):
            body = text[m.end() : end]
            _profile_writer(m.group(1), m.group(2), body, all_text, ref_uuid, profiles)
        for b in _BRANCH.finditer(text):
            uuid = ref_uuid(b.group(1) or b.group(2))
            if uuid is None:
                continue
            branch = text[b.end() : b.end() + _BRANCH_WINDOW]
            nxt = _BRANCH.search(branch)
            decode = _decode(branch[: nxt.start()] if nxt else branch)
            if decode:
                profiles.setdefault(uuid, CharProfile()).decode = decode
    return profiles


def _profile_writer(
    name: str,
    params: str,
    body: str,
    all_text: str,
    ref_uuid: Callable[[str], str | None],
    profiles: dict[str, CharProfile],
) -> None:
    if not (_WRITE.search(body) and _SET_VALUE.search(body)):
        return
    chars = {u for g in _GETCHAR.finditer(body) if (u := ref_uuid(g.group(1)))}
    if len(chars) != 1:
        return  # generic writer (the characteristic is a parameter) or several
    int_params = set(_INT_PARAM.findall(params))
    one_byte = _ONE_BYTE.search(body)
    if not one_byte or one_byte.group(1) not in int_params:
        return
    calls = re.findall(rf"\b{re.escape(name)}\(\s*(\d+)\s*\)", all_text)
    values = sorted({int(v) for v in calls})
    profile = profiles.setdefault(chars.pop(), CharProfile())
    profile.writer, profile.write_encoding, profile.values = name, "uint8", values


def _decode(branch: str) -> str | None:
    head = branch[:400]
    for pattern, kind in _DECODERS:
        if pattern.search(head):
            return kind
    first = _FIRST_BYTE.search(head)
    if first is None:
        return None
    var = first.group(1)
    if var and re.search(rf"\b{re.escape(var)}\s*!=\s*0\b", branch):
        return "bool"
    return "int8"  # a Java byte: signed, as the app reads it


def local_name_filter(texts: list[str]) -> str | None:
    """The advertised-name substring the app's scan keeps (FirePit), if any."""
    for text in texts:
        for m in re.finditer(r"\.getName\(\)", text):
            window = text[m.start() : m.start() + _NAME_WINDOW]
            f = _NAME_FILTER.search(window)
            if f:
                return f.group(1) or f.group(2)
    return None
