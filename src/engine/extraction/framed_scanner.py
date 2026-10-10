# SPDX-License-Identifier: MIT
"""P2-8c — Framed command protocols over one GATT write/notify pair.

Some vendors don't give each setting its own characteristic: every request is a
small binary frame written to one characteristic, and the device answers with
frames on another (JBL/Harman speakers: ``AA <opcode> <length> <payload>``).
The characteristic scanner sees two UUIDs and nothing else; this module reads
the protocol out of the app's command classes instead:

  frame      the base command class's serialiser: ``byte[] b = {getIdentifier(),
             this.command, (byte) getPayloadLen()}`` + payload → sync byte(s),
             opcode, length, payload (the sync value from the field's default)
  commands   each subclass's constructor: ``setCommand(PacketFormat.REQ_VER)``,
             ``setPayload(new byte[]{b})``, ``getResponseCommands().add(…)`` →
             opcode, payload layout (constructor parameters and literals) and the
             opcodes that answer it
  replies    the reply dispatcher: ``if (command == 98) device.setEqMode(
             Byte.parseByte(hex, 16))`` → opcode 0x62 carries one byte, eq_mode;
             a handler that formats the bytes as "a.b.c" → a version string; one
             that parses device-info tokens → the token list
  tokens     the token parser: ``retDevInfoTokenIds(4, PacketFormat.BATTERY_STATUS,
             …)`` → token 0x44, one byte; ``v >= 128 … v - 128 … Charging`` → level
             in the low 7 bits, bit 7 = charging; a length-prefixed name token
  transport  the write/notify/service UUIDs, which such apps often keep in an
             asset JSON (AppConfig.json: rxUUID, txUUID, bleRxTxUUID) rather than
             in code; their roles come from how the code uses each getter
  models     asset product tables (pid → name, link protocol, features)
  discovery  ``getManufacturerSpecificData(87)`` → the advertising company ID

Anything not understood is recorded as such (an ``unknown`` payload item, a reply
without a decoder) rather than guessed.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..ir.models import Direction, Endpoint, FieldDef, FieldKind, TransportType

_LOGGER = logging.getLogger(__name__)

_CONST = re.compile(
    r"public\s+static\s+final\s+(byte|int|short|String)\s+([A-Z][A-Z0-9_]*)\s*=\s*"
    r'(\(byte\)\s*-?\d+|-?\d+|"[^"]*")\s*;'
)
_CLASS = re.compile(
    r"\b(?:public\s+)?(?:final\s+)?(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?"
)
# byte[] bArr = {getIdentifier(), this.command, (byte) getPayloadLen()};
_HEADER = re.compile(r"byte\[\]\s+\w+\s*=\s*\{([^{}]+)\};")
_OPCODE_NAME = re.compile(r"^(?:command|cmd|opcode|op)$", re.IGNORECASE)
_LENGTH_NAME = re.compile(r"len|length|size", re.IGNORECASE)
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_TOKEN = re.compile(r"^[0-9a-fA-F]{2}$")


@dataclass
class FramedProtocol:
    frame: list[dict[str, Any]]
    commands: list[dict[str, Any]] = field(default_factory=list)
    replies: list[dict[str, Any]] = field(default_factory=list)
    tokens: list[dict[str, Any]] = field(default_factory=list)
    opcode_names: dict[int, str] = field(default_factory=dict)
    transport: dict[str, Any] = field(default_factory=dict)
    models: dict[str, dict[str, Any]] = field(default_factory=dict)
    manufacturer_ids: list[int] = field(default_factory=list)
    base_class: str = ""


# ── Java helpers ──────────────────────────────────────────────────────────────


def _block(text: str, open_brace: int) -> str:
    """The text between the brace at *open_brace* and its match."""
    depth = 0
    for i in range(open_brace, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : i]
    return text[open_brace + 1 :]


def _split_top(expr: str) -> list[str]:
    """Split on commas outside parentheses."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for c in expr:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _method_bodies(text: str) -> dict[str, str]:
    """method name → body, for the methods declared in *text*."""
    bodies: dict[str, str] = {}
    for m in re.finditer(
        r"^[ \t]+(?:(?:public|private|protected|static|final|synchronized)\s+)*"
        r"[\w.$]+(?:<[^(){};\n]*>)?(?:\[\])*\s+(\w+)\s*\([^)\n]*\)\s*(?:throws\s+[\w., ]+)?\{",
        text,
        re.MULTILINE,
    ):
        bodies.setdefault(m.group(1), _block(text, m.end() - 1))
    return bodies


def _snake(name: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


class _Constants:
    """Class.NAME → value for the app's static final byte/int/String constants."""

    def __init__(self, texts: dict[str, str]) -> None:
        self.by_class: dict[str, dict[str, int | str]] = {}
        for cls, text in texts.items():
            for kind, name, raw in _CONST.findall(text):
                value: int | str
                if kind == "String":
                    value = raw.strip('"')
                else:
                    value = int(re.sub(r"\(byte\)\s*", "", raw))
                self.by_class.setdefault(cls, {})[name] = value

    def lookup(self, ref: str) -> int | str | None:
        cls, _, name = ref.rpartition(".")
        if cls:
            return self.by_class.get(cls.split(".")[-1], {}).get(name)
        return None

    def name_of(self, cls: str, value: int | str) -> str | None:
        for name, v in self.by_class.get(cls, {}).items():
            if v == value:
                return name
        return None

    def byte(self, expr: str) -> int | None:
        """The byte an expression evaluates to, if it's a constant (0..255)."""
        e = expr.strip()
        e = re.sub(r"^Byte\.valueOf\((.*)\)$", r"\1", e).strip()
        e = re.sub(r"^\(byte\)\s*", "", e).strip()
        if e.startswith("(") and e.endswith(")") and e.count("(") == 1:
            e = e[1:-1].strip()
        if re.fullmatch(r"-?\d+", e):
            return int(e) & 0xFF
        if re.fullmatch(r"0x[0-9a-fA-F]+", e):
            return int(e, 16) & 0xFF
        m = re.fullmatch(
            r"Integer\.parseInt\(\s*([\w.\"]+)\s*,\s*(?:CharsKt\.checkRadix\()?16\)?\s*\)", e
        )
        if m:
            ref = m.group(1)
            text = ref.strip('"') if ref.startswith('"') else self.lookup(ref)
            if isinstance(text, str) and re.fullmatch(r"[0-9a-fA-F]+", text):
                return int(text, 16) & 0xFF
            return None
        if re.fullmatch(r"[\w.]+\.[A-Z][A-Z0-9_]*", e):
            v = self.lookup(e)
            if isinstance(v, int):
                return v & 0xFF
        return None


# ── scan ──────────────────────────────────────────────────────────────────────


def scan(root: Path, java_files: list[Path]) -> FramedProtocol | None:
    """The framed protocol in a decompiled app, or None if it has none."""
    texts: dict[str, str] = {}
    for path in java_files:
        try:
            texts[path.stem] = path.read_text(errors="replace")
        except OSError:
            continue
    base = _find_base(texts)
    if base is None:
        return None
    base_name, frame, setters = base
    consts = _Constants(texts)
    commands, opcode_class, used_names = _commands(texts, base_name, setters, consts)
    if not commands:
        return None
    proto = FramedProtocol(frame=frame, commands=commands, base_class=base_name)
    if opcode_class:
        proto.opcode_names = _opcode_names(consts.by_class.get(opcode_class, {}), used_names)
    proto.tokens = _tokens(texts, consts)
    proto.replies = _replies(texts, consts, bool(proto.tokens))
    _token_replies(proto)
    assets = root / "resources" / "assets"
    proto.transport = _transport(assets, texts)
    proto.models = _models(assets)
    proto.manufacturer_ids = _manufacturer_ids(texts, consts)
    _LOGGER.info(
        "framed_scanner: base %s, %d commands, %d replies, %d tokens",
        base_name,
        len(commands),
        len(proto.replies),
        len(proto.tokens),
    )
    return proto


def _find_base(
    texts: dict[str, str],
) -> tuple[str, list[dict[str, Any]], dict[str, str | None]] | None:
    """(class, frame layout, setter names) of the class that serialises frames."""
    for cls, text in texts.items():
        if not re.search(r"\bbyte\[\]\s+\w+\s*;", text):
            continue
        for m in _HEADER.finditer(text):
            parts = _split_top(m.group(1))
            frame: list[dict[str, Any]] = []
            opcode_field = None
            for p in parts:
                ref = re.sub(r"^\(byte\)\s*", "", p).strip()
                fname = _field_of(ref)
                if fname and _LENGTH_NAME.search(fname):
                    frame.append({"kind": "length"})
                elif fname and _OPCODE_NAME.match(fname):
                    frame.append({"kind": "opcode"})
                    opcode_field = fname
                else:
                    value = _field_default(text, fname) if fname else None
                    if value is None and re.fullmatch(r"-?\d+", ref):
                        value = int(ref) & 0xFF
                    if value is None:
                        frame = []
                        break
                    frame.append({"kind": "const", "value": value})
            kinds = [f["kind"] for f in frame]
            if kinds.count("opcode") != 1 or kinds.count("length") != 1:
                continue
            # The serialiser appends the payload after the header.
            if not re.search(
                r"System\.arraycopy\(\s*this\.\w+|payload", text[m.end() : m.end() + 600]
            ):
                continue
            frame.append({"kind": "payload"})
            assert opcode_field is not None
            setters = {
                "opcode": "set" + opcode_field[0].upper() + opcode_field[1:],
                "payload": _payload_setter(text),
                "replies": _replies_getter(text),
            }
            return cls, frame, setters
    return None


def _field_of(ref: str) -> str | None:
    """this.command → command; getPayloadLen() → payloadLen; getIdentifier() → identifier."""
    m = re.fullmatch(r"(?:this\.)?(\w+)", ref)
    if m and not m.group(1).isdigit():
        return m.group(1)
    m = re.fullmatch(r"(?:this\.)?get(\w+)\(\)", ref)
    if m:
        return m.group(1)[0].lower() + m.group(1)[1:]
    return None


def _field_default(text: str, fname: str) -> int | None:
    m = re.search(rf"this\.{re.escape(fname)}\s*=\s*\(byte\)\s*(-?\d+)\s*;", text)
    if m is None:
        m = re.search(rf"\bbyte\s+{re.escape(fname)}\s*=\s*\(byte\)\s*(-?\d+)\s*;", text)
    return int(m.group(1)) & 0xFF if m else None


def _payload_setter(text: str) -> str:
    m = re.search(r"public\s+(?:final\s+)?void\s+(set\w*)\(\s*byte\[\]\s+\w+\s*\)", text)
    return m.group(1) if m else "setPayload"


def _replies_getter(text: str) -> str | None:
    m = re.search(r"(?:protected|public)\s+(?:final\s+)?\w*List<Byte>\s+(get\w+)\(\)", text)
    return m.group(1) if m else None


def _subclasses(texts: dict[str, str], base: str) -> dict[str, str]:
    """Direct subclasses of *base* that don't serialise frames their own way."""
    out: dict[str, str] = {}
    for cls, text in texts.items():
        m = _CLASS.search(text)
        if m and m.group(1) == cls and m.group(2) == base:
            if re.search(r"public\s+byte\[\]\s+data\(\)", text):
                continue  # its own frame format (long/segmented commands)
            out[cls] = text
    return out


def _commands(
    texts: dict[str, str], base: str, setters: dict[str, str | None], consts: _Constants
) -> tuple[list[dict[str, Any]], str | None, set[str]]:
    commands: list[dict[str, Any]] = []
    opcode_refs: dict[str, int] = {}
    used_names: set[str] = set()  # constants the commands use as opcodes
    op_setter = re.escape(setters["opcode"] or "setCommand")
    pl_setter = re.escape(setters["payload"] or "setPayload")
    for cls, text in sorted(_subclasses(texts, base).items()):
        ctor = re.search(rf"public\s+{re.escape(cls)}\s*\(([^)]*)\)\s*\{{", text)
        if ctor is None:
            continue
        body = _block(text, ctor.end() - 1)
        op = re.search(rf"(?:super\.)?{op_setter}\(\s*(.+?)\s*\);", body)
        if op is None:
            continue
        opcode = consts.byte(op.group(1))
        if opcode is None:
            continue
        ref = re.search(r"([A-Z]\w+)\.([A-Z][A-Z0-9_]*)", op.group(1))
        if ref:
            opcode_refs[ref.group(1)] = opcode_refs.get(ref.group(1), 0) + 1
            used_names.add(ref.group(2))
        params = _params(ctor.group(1))
        aliases = dict(re.findall(r"this\.(\w+)\s*=\s*(\w+)\s*;", body))
        payload: list[dict[str, Any]] = []
        pm = re.search(rf"{pl_setter}\(\s*new\s+byte\[\]\s*\{{(.*?)\}}\s*\);", body, re.DOTALL)
        if pm:
            payload = [_payload_item(e, params, aliases, consts) for e in _split_top(pm.group(1))]
        replies: list[int] = []
        token_ids = False  # replies written as Integer.parseInt(<hex token>): token ids
        if setters["replies"]:
            adds = re.findall(rf"{re.escape(setters['replies'])}\(\)\.add\(\s*(.+?)\s*\);", body)
            token_ids = bool(adds) and all("parseInt" in a for a in adds)
            for a in adds:
                v = consts.byte(a)
                if v is not None:
                    replies.append(v)
                    if "parseInt" not in a:
                        used_names.update(re.findall(r"\.([A-Z][A-Z0-9_]*)", a))
        name = re.sub(r"Command$", "", cls)
        commands.append(
            {
                "name": name,
                "class": cls,
                "opcode": opcode,
                "payload": payload,
                "params": [p for p in params if any(i.get("param") == p["name"] for i in payload)],
                "replies": replies,
                "replies_are_tokens": token_ids,
                "kind": "request"
                if re.match(r"(?:Req|Get)[A-Z]", name)
                else "set"
                if name.startswith("Set")
                else "other",
                "complete": all("unknown" not in i for i in payload),
            }
        )
    opcode_class = max(opcode_refs, key=lambda k: opcode_refs[k]) if opcode_refs else None
    return commands, opcode_class, used_names


def _opcode_names(consts: dict[str, int | str], used: set[str]) -> dict[int, str]:
    """value → name, preferring the constants the code uses as opcodes.

    Opcode tables reuse values across unrelated constants (RET_DEV_INFO = 18 =
    DISABLE_EQ_FEATURE): an unused name is taken only if it has the same prefix
    (RET_, REQ_, …) as names the code does use.
    """
    prefixes = {n.split("_")[0] for n in used}
    names: dict[int, str] = {}
    for pass_used in (True, False):
        for name, v in consts.items():
            ok = name in used if pass_used else name.split("_")[0] in prefixes
            if isinstance(v, int) and ok:
                names.setdefault(v & 0xFF, name)
    return names


def _token_replies(proto: FramedProtocol) -> None:
    """Requests that list token ids as their replies are answered by the token reply."""
    token_reply = next((r["opcode"] for r in proto.replies if r["decode"] == "tokens"), None)
    for c in proto.commands:
        if c.pop("replies_are_tokens", False) and token_reply is not None:
            c["replies"] = [token_reply]


def _params(sig: str) -> list[dict[str, str]]:
    out = []
    for p in _split_top(sig):
        bits = p.split()
        if len(bits) >= 2:
            out.append({"name": bits[-1], "type": bits[-2]})
    return out


def _payload_item(
    expr: str, params: list[dict[str, str]], aliases: dict[str, str], consts: _Constants
) -> dict[str, Any]:
    value = consts.byte(expr)
    if value is not None:
        return {"value": value}
    names = {p["name"]: p["type"] for p in params}
    e = re.sub(r"^\(byte\)\s*", "", expr.strip())
    e = re.sub(r"^this\.(\w+)$", lambda m: aliases.get(m.group(1), m.group(0)), e)
    if e in names and names[e] in ("byte", "int", "short"):
        return {"param": e, "type": names[e]}
    # (byte) (i == -1 ? 0 : i): the parameter, with a default for its "unset" value
    m = re.fullmatch(r"\(\s*(\w+)\s*==\s*-?\d+\s*\?\s*(-?\d+)\s*:\s*\1\s*\)", e)
    if m and m.group(1) in names:
        return {"param": m.group(1), "type": names[m.group(1)], "default": int(m.group(2))}
    return {"unknown": expr.strip()}


# ── replies ───────────────────────────────────────────────────────────────────

# if (command == 98 || command == 100) {  /  if (66 == receivedCommand.getCommand()) {
_OPCODE_TEST = re.compile(
    r"if\s*\(([^{;]*?(?:\bcommand\b|getCommand\(\))\s*==\s*[^{;]*?)\)\s*\{"
    r"|if\s*\(([^{;]*?(?:-?\d+|[A-Z]\w*\.[A-Z][A-Z0-9_]*)\s*==\s*\w+\.getCommand\(\)[^{;]*?)\)\s*\{"
)
_EQ_OPERAND = re.compile(
    r"(?:\bcommand\b|getCommand\(\))\s*==\s*(-?\d+|[A-Z]\w*\.[A-Z][A-Z0-9_]*)"
    r"|(-?\d+|[A-Z]\w*\.[A-Z][A-Z0-9_]*)\s*==\s*\w+\.getCommand\(\)"
)
_SET_PARSED_BYTE = re.compile(r"\.set(\w+)\(\s*Byte\.parseByte\(\s*\w+\s*,")


def _replies(texts: dict[str, str], consts: _Constants, have_tokens: bool) -> list[dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    for text in texts.values():
        bodies: dict[str, str] | None = None
        for m in _OPCODE_TEST.finditer(text):
            cond = m.group(1) or m.group(2)
            ops = [
                o for a, b in _EQ_OPERAND.findall(cond) if (o := consts.byte(a or b)) is not None
            ]
            if not ops:
                continue
            block = _block(text, m.end() - 1)
            if bodies is None:
                bodies = _method_bodies(text)
            spec = _reply_decoder(block, bodies, have_tokens)
            if spec is None:
                continue
            for op in ops:
                found.setdefault(op, {"opcode": op, **spec})
    return [found[k] for k in sorted(found)]


def _reply_decoder(block: str, bodies: dict[str, str], have_tokens: bool) -> dict[str, Any] | None:
    head = block[:1200]
    s = _SET_PARSED_BYTE.search(head)
    if s:
        return {"decode": "uint8", "field": _snake(s.group(1))}
    for call in re.findall(r"\b(process\w+|parse\w+)\(", head):
        body = bodies.get(call, "")
        if have_tokens and _uses_tokens(body, bodies):
            return {"decode": "tokens"}
        version_fn = _version_formatter(body, bodies)
        if version_fn:
            setter = re.search(r"\.set(\w*(?:Ver|Version)\w*)\(", body)
            name = _snake(setter.group(1)) if setter else "version"
            return {
                "decode": "version",
                "field": "firmware_version" if "firmware" in name else name,
            }
    return None


def _uses_tokens(body: str, bodies: dict[str, str], depth: int = 2) -> bool:
    if re.search(r"\w+\(\s*\d+\s*,\s*[A-Z]\w*\.[A-Z][A-Z0-9_]*\s*,", body):
        return True
    if depth == 0:
        return False
    return any(
        _uses_tokens(bodies[c], bodies, depth - 1)
        for c in set(re.findall(r"\b(\w+)\(", body))
        if c in bodies and bodies[c] is not body
    )


def _version_formatter(body: str, bodies: dict[str, str]) -> bool:
    """The body (or a method it calls) joins the payload's bytes with dots."""
    for c in [None, *re.findall(r"\b(\w+)\(", body)]:
        b = body if c is None else bodies.get(c, "")
        if 'append(".")' in b and re.search(r"substring\(\s*\w+\s*,\s*\w+\s*\)", b):
            return True
    return False


# ── tokens ────────────────────────────────────────────────────────────────────

# retDevInfoTokenIds(4, PacketFormat.BATTERY_STATUS, rest) → token var, hex chars incl. token
_TOKEN_CALL = re.compile(
    r"String\[\]\s+(\w+)\s*=\s*\w+\(\s*(\d+)\s*,\s*([A-Z]\w*\.[A-Z][A-Z0-9_]*)\s*,"
)


def _tokens(texts: dict[str, str], consts: _Constants) -> list[dict[str, Any]]:
    tokens: dict[int, dict[str, Any]] = {}
    for text in texts.values():
        for m in _TOKEN_CALL.finditer(text):
            arr, hex_len, ref = m.group(1), int(m.group(2)), m.group(3)
            tid = consts.lookup(ref)
            if not (isinstance(tid, str) and _HEX_TOKEN.match(tid)) or hex_len % 2 or hex_len < 4:
                continue
            name = ref.rpartition(".")[2].lower()
            name = re.sub(r"_token_id$", "", name)
            var = re.search(rf"String\s+(\w+)\s*=\s*{re.escape(arr)}\[0\]\s*;", text[m.end() :])
            encoding = _token_encoding(text[m.end() :], var.group(1) if var else None, name)
            tokens.setdefault(
                int(tid, 16),
                {"id": int(tid, 16), "name": name, "size": hex_len // 2 - 1, "encoding": encoding},
            )
        # Length-prefixed tokens: a reader that takes the byte after the token as a
        # length (``Integer.valueOf(len, 16).intValue() * 2``), called with the token.
        if "* 2" not in text:
            continue
        for name, body in _method_bodies(text).items():
            if not re.search(
                r"Integer\.valueOf\(\s*\w+\s*,\s*16\s*\)\.intValue\(\)\s*\*\s*2", body
            ):
                continue
            for call in re.finditer(
                rf"\b{re.escape(name)}\(\s*(\"[0-9a-fA-F]{{2}}\"|[A-Z]\w*\.[A-Z][A-Z0-9_]*)\s*,",
                text,
            ):
                arg = call.group(1)
                tid = arg.strip('"') if arg.startswith('"') else consts.lookup(arg)
                if not isinstance(tid, str) or not _HEX_TOKEN.match(tid):
                    continue
                const_name = (
                    next(
                        (
                            n
                            for vals in consts.by_class.values()
                            for n, v in vals.items()
                            if v == tid and isinstance(v, str) and not n.endswith("_TOKEN_ID")
                        ),
                        None,
                    )
                    if arg.startswith('"')
                    else arg.rpartition(".")[2]
                )
                after = text[call.end() : call.end() + 600]
                encoding = "utf8" if "hexStringToString" in after else "hex"
                tokens.setdefault(
                    int(tid, 16),
                    {
                        "id": int(tid, 16),
                        "name": (const_name or f"token_{tid}").lower(),
                        "size": None,
                        "encoding": encoding,
                    },
                )
    return [tokens[k] for k in sorted(tokens)]


def _token_encoding(after: str, var: str | None, name: str) -> str:
    if var is None:
        return "hex"
    window = after[:6000]
    iv = re.search(rf"int\s+(\w+)\s*=\s*\w+\.parseHex\w*\(\s*{re.escape(var)}\b", window)
    if iv:
        n = re.escape(iv.group(1))
        if (
            re.search(rf"\b{n}\s*>=\s*128", window)
            and re.search(rf"\b{n}\s*-\s*128", window)
            and "Charging" in window
        ):
            return "level_charging_bit7"
        return "uint"
    return "hex"


# ── transport, models, discovery ──────────────────────────────────────────────


def _asset_json(assets: Path) -> list[tuple[Path, Any]]:
    out: list[tuple[Path, Any]] = []
    if not assets.is_dir():
        return out
    for p in sorted(assets.rglob("*.json")):
        try:
            if p.stat().st_size > 2_000_000:
                continue
            out.append((p, json.loads(p.read_text(errors="replace"))))
        except OSError, ValueError:
            continue
    return out


def _transport(assets: Path, texts: dict[str, str]) -> dict[str, Any]:
    """Service/write/notify UUIDs from an asset config, roles from the code's use of them."""
    all_text = "\n".join(texts.values())
    for path, data in _asset_json(assets):
        if not isinstance(data, dict):
            continue
        uuids = {k: v.lower() for k, v in data.items() if isinstance(v, str) and _UUID.match(v)}
        if len(uuids) < 2:
            continue
        roles: dict[str, str] = {}
        for key in uuids:
            getter = "get" + key[0].upper() + key[1:] + "()"
            if getter not in all_text:
                continue
            roles[key] = _uuid_role(all_text, getter)
        notify = [k for k, r in roles.items() if r == "notify"]
        write = [k for k, r in roles.items() if r == "write"]
        service = [k for k, r in roles.items() if r == "service"]
        if len(notify) == 1 and len(write) == 1:
            prefix = uuids[notify[0]][:24]
            # The service the pair lives in: the one from the same UUID family.
            services = [k for k in service if uuids[k].startswith(prefix)] or service
            return {
                "source": f"assets/{path.relative_to(assets).as_posix()}",
                "service": uuids[services[0]] if services else None,
                "notify": uuids[notify[0]],
                "write": uuids[write[0]],
                "keys": {"notify": notify[0], "write": write[0]},
            }
    return {}


def _uuid_role(text: str, getter: str) -> str:
    """notify / write / service / other for a config getter (getRxUUID())."""
    for g in re.finditer(re.escape(getter), text):
        stmt_start = text.rfind(";", 0, g.start()) + 1
        m = re.search(r"(\w+)\s*=\s*UUID\.fromString\(", text[stmt_start : g.start()])
        if m is None:
            continue
        var = re.escape(m.group(1))
        window = text[g.end() : g.end() + 6000]
        if re.search(rf"getService\(\s*{var}\s*\)", window):
            return "service"
        ch = re.search(rf"(\w+)\s*=\s*\w+\.getCharacteristic\(\s*{var}\s*\)", window)
        if ch:
            c = re.escape(ch.group(1))
            if re.search(rf"setCharacteristicNotification\(\s*{c}\b", window):
                return "notify"
            return "write"  # held for writes (the app writes to it elsewhere)
    return "other"


def _models(assets: Path) -> dict[str, dict[str, Any]]:
    models: dict[str, dict[str, Any]] = {}

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            pid = node.get("pid")
            name = node.get("deviceName") or node.get("productName")
            if (
                isinstance(pid, str)
                and re.fullmatch(r"[0-9a-fA-F]{4}", pid)
                and isinstance(name, str)
            ):
                entry = models.setdefault(pid.lower(), {"name": name})
                if isinstance(node.get("protocol"), str):
                    entry["protocol"] = node["protocol"]
                if isinstance(node.get("features"), list):
                    entry["features"] = [f for f in node["features"] if isinstance(f, str)]
            for v in node.values():
                visit(v)
        elif isinstance(node, list):
            for v in node:
                visit(v)

    for _, data in _asset_json(assets):
        visit(data)
    return dict(sorted(models.items()))


def _manufacturer_ids(texts: dict[str, str], consts: _Constants) -> list[int]:
    ids: list[int] = []
    for text in texts.values():
        for m in re.finditer(r"getManufacturerSpecificData\(\s*([\w.]+)\s*\)", text):
            arg = m.group(1)
            v: int | str | None = int(arg) if arg.isdigit() else consts.lookup(arg)
            if isinstance(v, int) and v not in ids:
                ids.append(v)
    return ids


# ── IR ────────────────────────────────────────────────────────────────────────


def endpoints(proto: FramedProtocol) -> tuple[list[Endpoint], list[Endpoint]]:
    """Commands (requests and settings) and replies as IR endpoints."""
    commands = [
        Endpoint(
            cmd=c["name"],
            transport=TransportType.BLE,
            direction=Direction.TO_DEVICE,
            awaits_response=bool(c["replies"]),
            request_fields=[FieldDef(name=p["name"], kind=FieldKind.INTEGER) for p in c["params"]],
            description=f"opcode 0x{c['opcode']:02x}",
            source_class=c["class"],
            confidence=1.0 if c["complete"] else 0.5,
        )
        for c in proto.commands
    ]
    events = [
        Endpoint(
            cmd=proto.opcode_names.get(r["opcode"], f"reply_0x{r['opcode']:02x}"),
            transport=TransportType.BLE,
            direction=Direction.FROM_DEVICE,
            response_fields=(
                [FieldDef(name=t["name"], kind=FieldKind.STRING) for t in proto.tokens]
                if r["decode"] == "tokens"
                else [
                    FieldDef(
                        name=r["field"],
                        kind=FieldKind.INTEGER if r["decode"] == "uint8" else FieldKind.STRING,
                    )
                ]
            ),
            description=f"opcode 0x{r['opcode']:02x}",
        )
        for r in proto.replies
    ]
    return commands, events


def to_extra(proto: FramedProtocol) -> dict[str, Any]:
    d = asdict(proto)
    d["opcode_names"] = {f"0x{k:02x}": v for k, v in sorted(proto.opcode_names.items())}
    return d
