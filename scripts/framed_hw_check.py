#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check an extracted framed protocol against a real device (read-only).

Builds every request the IR knows how to decode the answer to, sends it to the
device, and decodes the replies with the reference codec, so the extraction is
checked against hardware rather than against a fake built from the same reading
of the code.

Only *requests* are sent (commands named Req…/Get…) whose reply has a decoder;
anything that sounds like a firmware update, authentication, analytics or a
disconnect is skipped. Nothing is ever set on the device.

Links:
  --ble ADDR      GATT over BLE (bleak)
  --classic ADDR  GATT over classic Bluetooth (BR/EDR): ATT on L2CAP PSM 31.
                  For models the app talks to that way (JBL Flip 6, Pulse 5,
                  BoomBox 2/3). Pair the device first (bluetoothctl pair ADDR).
                  Linux only, and needs a Python built with Bluetooth sockets
                  (the system python3; uv's standalone builds lack AF_BLUETOOTH).

A request the device doesn't answer is reported, not failed: models implement
subsets of the protocol. The check fails when nothing answers, or when an
answer's decoder yields nothing (the extraction misread the reply).

Usage:  python3 scripts/framed_hw_check.py --classic 10:28:74:3C:0D:87 \\
            [--ir .cache/checkpoints/jbl_portable.json] [--timeout 2]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import socket
import struct
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from engine.extraction import framed_codec as codec  # noqa: E402

_UNSAFE = re.compile(r"dfu|ota|upgrade|update|auth|analytic|clear|disconnect|identif|role", re.I)


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    ir = data.get("ir", data)
    framed = ir.get("extra", {}).get("framed")
    if not framed:
        sys.exit(f"{path}: no framed protocol in this IR")
    return framed


def _requests(framed: dict[str, Any]) -> list[dict[str, Any]]:
    decodable = {r["opcode"] for r in framed["replies"]}
    return [
        c
        for c in framed["commands"]
        if c["kind"] == "request"
        and c["complete"]
        and not _UNSAFE.search(c["name"])
        and set(c["replies"]) & decodable
        and all("value" in i or "default" in i for i in c["payload"])
    ]


# ── links ─────────────────────────────────────────────────────────────────────


class _ClassicAtt:
    """Just enough ATT for one write/notify pair (GATT over BR/EDR, Linux)."""

    def __init__(self, addr: str) -> None:
        self.addr = addr
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        self.sock.setblocking(False)
        self.on_notify: Callable[[bytes], None] = lambda _: None
        self._pending: asyncio.Future[bytes] | None = None
        self._reader: asyncio.Task[None] | None = None

    async def open(self, service: str, notify: str, write: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.sock_connect(self.sock, (self.addr, 31))
        self._reader = asyncio.create_task(self._read())
        chars = await self._characteristics()
        handles = {u: h for h, u in chars}
        if notify not in handles or write not in handles:
            raise SystemExit(f"device has no {notify} / {write}: {sorted(handles)}")
        self.write_handle = handles[write]
        cccd = await self._cccd(handles[notify], max(h for h, _ in chars) + 0x10)
        await self._request(struct.pack("<BH", 0x12, cccd) + b"\x01\x00")

    async def _read(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            pdu = await loop.sock_recv(self.sock, 1024)
            if not pdu:
                return
            if pdu[0] in (0x1B, 0x1D):  # notification / indication
                if pdu[0] == 0x1D:
                    await loop.sock_sendall(self.sock, b"\x1e")
                self.on_notify(pdu[3:])
            elif self._pending and not self._pending.done():
                self._pending.set_result(pdu)

    async def _request(self, pdu: bytes) -> bytes:
        self._pending = asyncio.get_running_loop().create_future()
        await asyncio.get_running_loop().sock_sendall(self.sock, pdu)
        return await asyncio.wait_for(self._pending, 5)

    async def _characteristics(self) -> list[tuple[int, str]]:
        out, start = [], 1
        while start <= 0xFFFF:
            r = await self._request(struct.pack("<BHHH", 0x08, start, 0xFFFF, 0x2803))
            if r[0] != 0x09:
                break
            n = r[1]
            for i in range(2, len(r), n):
                decl, _props, handle = struct.unpack("<HBH", r[i : i + 5])
                out.append((handle, _uuid(r[i + 5 : i + n])))
                start = decl + 1
        return out

    async def _cccd(self, value_handle: int, end: int) -> int:
        r = await self._request(struct.pack("<BHH", 0x04, value_handle + 1, end))
        if r[0] == 0x05 and r[1] == 1:
            for i in range(2, len(r), 4):
                if r[i + 2 : i + 4] == b"\x02\x29":
                    return int.from_bytes(r[i : i + 2], "little")
        raise SystemExit("no notification descriptor on the notify characteristic")

    async def write(self, data: bytes) -> None:
        await asyncio.get_running_loop().sock_sendall(
            self.sock, struct.pack("<BH", 0x52, self.write_handle) + data
        )

    async def close(self) -> None:
        if self._reader:
            self._reader.cancel()
        self.sock.close()


class _Ble:
    def __init__(self, addr: str) -> None:
        from bleak import BleakClient

        self.client = BleakClient(addr, timeout=20)
        self.on_notify: Callable[[bytes], None] = lambda _: None

    async def open(self, service: str, notify: str, write: str) -> None:
        await self.client.connect()
        self.write_uuid = write
        await self.client.start_notify(notify, lambda _, d: self.on_notify(bytes(d)))

    async def write(self, data: bytes) -> None:
        await self.client.write_gatt_char(self.write_uuid, data, response=False)

    async def close(self) -> None:
        await self.client.disconnect()


def _uuid(b: bytes) -> str:
    if len(b) == 2:
        return f"0000{int.from_bytes(b, 'little'):04x}-0000-1000-8000-00805f9b34fb"
    h = b[::-1].hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


# ── check ─────────────────────────────────────────────────────────────────────


async def check(link: Any, framed: dict[str, Any], reply_wait: float) -> int:
    frame = framed["frame"]
    replies = {r["opcode"]: r for r in framed["replies"]}
    tokens = {t["id"]: t for t in framed["tokens"]}
    names = {int(k, 16): v for k, v in framed.get("opcode_names", {}).items()}
    t = framed["transport"]
    inbox: asyncio.Queue[bytes] = asyncio.Queue()
    link.on_notify = inbox.put_nowait
    await link.open(t["service"], t["notify"], t["write"])
    state: dict[str, Any] = {}
    answered: list[str] = []
    unanswered: list[str] = []
    undecoded: list[str] = []
    try:
        for cmd in _requests(framed):
            req = codec.encode(frame, cmd["opcode"], codec.command_payload(cmd))
            print(f"{cmd['name']:<22} -> {req.hex()}")
            await link.write(req)
            got: set[int] = set()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + reply_wait
            while (left := deadline - loop.time()) > 0:
                try:
                    data = await asyncio.wait_for(inbox.get(), left)
                except TimeoutError:
                    break
                for opcode, payload in codec.frames(frame, data):
                    got.add(opcode)
                    spec = replies.get(opcode)
                    decoded = codec.decode_reply(spec, payload, tokens) if spec else {}
                    label = names.get(opcode, f"0x{opcode:02x}")
                    print(f"{'':<22} <- {label:<24} {payload.hex():<20} {decoded or ''}")
                    if opcode in cmd["replies"] and spec and not decoded:
                        undecoded.append(f"{cmd['name']}: {label} {payload.hex()}")
                    if decoded.get("device_index", 0) == 0:
                        state.update({k: v for k, v in decoded.items() if k != "device_index"})
            if got & set(cmd["replies"]):
                answered.append(cmd["name"])
            else:
                unanswered.append(cmd["name"])
                print(f"{'':<22} -- no {[hex(o) for o in cmd['replies']]} reply")
    finally:
        await link.close()
    print("\nstate:", json.dumps(state, indent=2))
    print(f"\nanswered:   {len(answered)}  {', '.join(answered)}")
    # Models implement subsets of the protocol: silence is "not on this model".
    print(f"unanswered: {len(unanswered)}  {', '.join(unanswered)}  (not supported by this model?)")
    for u in undecoded:
        print(f"UNDECODED:  {u}")
    return len(undecoded) + (0 if answered else 1)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    link = ap.add_mutually_exclusive_group(required=True)
    link.add_argument("--ble", metavar="ADDR")
    link.add_argument("--classic", metavar="ADDR")
    ap.add_argument("--ir", type=Path, default=_ROOT / ".cache/checkpoints/jbl_portable.json")
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()
    framed = _load(args.ir)
    dev = _ClassicAtt(args.classic) if args.classic else _Ble(args.ble)
    problems = asyncio.run(check(dev, framed, args.timeout))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
