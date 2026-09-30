# SPDX-License-Identifier: MIT
"""Challenge-response profile: everything a client needs to authenticate, from code.

Given a challenge-response device (see ble_scanner._detect_challenge_auth), work
out from first-party source and the IR:

  roles        which characteristics carry the device nonce, our public key, our
               nonce, the signature, the acknowledgement and the action code
  message      what is signed, in order (from the signing trace)
  algorithm    e.g. SHA256withECDSA on a secp256r1 key → "ecdsa-p256-sha256"
  encodings    raw r‖s vs DER signatures; compressed vs uncompressed public key
  nonce length our nonce size (new byte[N] + SecureRandom.nextBytes)
  actions      the app's main action code, and a probe code that authenticates
               without actuating (an admin/permission check)

Anything not established stays None; ``ChallengeResponseProfile.missing`` lists it,
and emission refuses an incomplete profile rather than guess.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..ir.models import ChallengeResponseProfile, CryptoUsage, Endpoint, SigningTrace
from .app_sources import app_source_files

_CURVES = {"secp256r1": "p256", "prime256v1": "p256", "secp384r1": "p384"}
_CURVE_RE = re.compile(r'ECGenParameterSpec\(\s*"(\w+)"\s*\)')
# DER → raw conversion: checks the SEQUENCE (0x30 = 48) and INTEGER (0x02) tags.
_DER_TO_RAW = re.compile(r"!=\s*48\b[\s\S]{0,400}?!=\s*2\b")
# SEC1 point compression: 0x02/0x03 prefix chosen by the y parity, 33-byte output.
_COMPRESS = re.compile(r"\(byte\)\s*3\s*:\s*\(byte\)\s*2|new\s+byte\[33\]")
_RANDOM_NONCE = re.compile(
    r"new\s+byte\[(\d+)\];\s*\n?\s*new\s+SecureRandom\(\)\.nextBytes\(|"
    r"SecureRandom\(\)\.nextBytes\(\s*new\s+byte\[(\d+)\]"
)
# authenticate(device, view, 1) / authenticate(2, callback): action codes.
_AUTH_CALL = re.compile(r"\b\w*[Aa]uthenticate\w*\s*\(([^;]*?)\)\s*;")
_INT_ARG = re.compile(r"(?:^|,)\s*(\d{1,3})\s*(?=,|$)")
# Probe actions set a high "permission check" bit and don't actuate the device.
_PROBE_BIT = 0x80


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def build(
    challenge: str,
    proof: str,
    commands: list[Endpoint],
    events: list[Endpoint],
    crypto: list[CryptoUsage],
    traces: list[SigningTrace],
    apk_out_dir: Path,
    app_package: str,
    launcher_activity: str | None,
) -> ChallengeResponseProfile:
    writes = [c.cmd for c in commands]
    reads = [e.cmd for e in events]

    def find(names: list[str], pattern: str, exclude: str | None = None) -> str | None:
        rx, ex = re.compile(pattern, re.I), re.compile(exclude, re.I) if exclude else None
        return next((n for n in names if rx.search(n) and not (ex and ex.search(n))), None)

    client_nonce = find(writes, r"client.*nonce|nonce.*client")
    client_key = find(writes, r"client.*key|public.*key", exclude=r"ack")
    ack = find(reads, r"auth.*ack|ack.*auth")
    action = find(writes, r"^action$")

    sources = apk_out_dir / "sources"
    texts = (
        [f.read_text(errors="replace") for f in app_source_files(sources, app_package)]
        if sources.exists()
        else []
    )
    all_src = "\n".join(texts)

    signing = next((t for t in traces if "ECDSA" in t.algorithm.upper()), None)
    message: list[str] = []
    if signing:
        roles = {_norm(challenge): "challenge", _norm(client_nonce or ""): "client_nonce"}
        message = [roles.get(_norm(c.variable_name), "?") for c in signing.components]
        if "?" in message:
            message = []  # an unidentified component: don't guess the layout

    curve = next((_CURVES.get(m) for m in _CURVE_RE.findall(all_src) if m in _CURVES), None)
    algorithm = None
    if curve and any(u.algorithm.upper() == "SHA256WITHECDSA" for u in crypto):
        algorithm = f"ecdsa-{curve}-sha256"

    nonce_len = next((int(a or b) for a, b in _RANDOM_NONCE.findall(all_src) if (a or b)), None)

    codes: dict[int, bool] = {}  # code → used in the launcher activity
    for text, path_name in zip(texts, _names(sources, app_package), strict=True):
        for call in _AUTH_CALL.finditer(text):
            for code in _INT_ARG.findall(call.group(1)):
                n = int(code)
                codes[n] = codes.get(n, False) or path_name == (launcher_activity or "")
    probe = next((c for c in sorted(codes) if c & _PROBE_BIT), None)
    primary = next(
        (c for c, launcher in sorted(codes.items()) if launcher and not c & _PROBE_BIT), None
    )

    # `if (this.$action == 1) { …readCharacteristic(gatt, …getNONCE_UUID()) …}`: that code
    # skips the action write and goes straight to the challenge.
    implicit = re.search(
        r"action\s*==\s*(\d+)\)\s*\{(?:(?!writeCharacteristic)[\s\S]){0,400}?"
        rf"readCharacteristic\([^;]*{re.escape(challenge)}",
        all_src,
        re.IGNORECASE,
    )

    return ChallengeResponseProfile(
        challenge=challenge,
        proof=proof,
        ack=ack,
        client_key=client_key,
        client_nonce=client_nonce,
        client_nonce_length=nonce_len,
        message=message,
        algorithm=algorithm,
        signature_encoding="raw_rs"
        if _DER_TO_RAW.search(all_src)
        else ("der" if signing else None),
        public_key_encoding=(
            "sec1_compressed"
            if _COMPRESS.search(all_src)
            else ("sec1_uncompressed" if curve else None)
        ),
        action=action,
        primary_action=primary,
        probe_action=probe,
        implicit_action=int(implicit.group(1)) if implicit else None,
    )


def _names(sources: Path, app_package: str) -> list[str]:
    """Simple class names, aligned with the texts list (for launcher-activity matching)."""
    if not sources.exists():
        return []
    return [f.stem.split("$")[0] for f in app_source_files(sources, app_package)]
