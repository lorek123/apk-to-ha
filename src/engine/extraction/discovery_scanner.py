# SPDX-License-Identifier: MIT
"""P5-7 — Auto-discovery extraction.

Scans decompiled Java source for mDNS/NSD and UDP broadcast patterns and
returns an enriched DiscoveryMechanism.

Detected signals (in priority order):
  1. NsdManager.discoverServices("_type._tcp") → ZEROCONF with service_type
  2. NsdServiceInfo.setServiceType("_type._tcp") → ZEROCONF with service_type
  3. String constant matching SERVICE_TYPE / MDNS_TYPE pattern
  4. JmDNS ServiceInfo.create("_type._tcp.", ...) → ZEROCONF with service_type
  5. MulticastLock or CHANGE_WIFI_MULTICAST_STATE permission → ZEROCONF (no type)
  6. DatagramSocket/DatagramPacket → UDP_BROADCAST with port extraction
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..ir.models import DiscoveryMechanism, DiscoveryType

_LOGGER = logging.getLogger(__name__)

# ── Java source patterns ───────────────────────────────────────────────────────

# NsdManager.discoverServices("_type._tcp", ...)
_NSD_DISCOVER_RE = re.compile(r'discoverServices\s*\(\s*"([^"]+\._(?:tcp|udp)\.?)"')

# nsdServiceInfo.setServiceType("_type._tcp")
_NSD_SET_TYPE_RE = re.compile(r'setServiceType\s*\(\s*"([^"]+\._(?:tcp|udp)\.?)"')

# String constant: SERVICE_TYPE = "_device._tcp" or similar
_MDNS_CONST_RE = re.compile(
    r'(?:SERVICE_TYPE|MDNS_TYPE|NSD_TYPE|ZEROCONF_TYPE)\s*=\s*"([^"]+\._(?:tcp|udp)\.?)"',
    re.I,
)

# JmDNS: ServiceInfo.create("_type._tcp.", name, port, text)
_JMDNS_CREATE_RE = re.compile(r'ServiceInfo\.create\s*\(\s*"([^"]+\._(?:tcp|udp)\.?)"')

# registerService(serviceInfo, ...) with inline service type
_NSD_REGISTER_RE = re.compile(r'registerService\s*\(\s*"([^"]+\._(?:tcp|udp)\.?)"')

_MULTICAST_RE = re.compile(r"createMulticastLock|MulticastLock|CHANGE_WIFI_MULTICAST_STATE")
_DATAGRAM_RE = re.compile(r"DatagramSocket|DatagramPacket|UDPServer|DatagramChannel")
_UDP_PORT_RE = re.compile(r"(?:SERVER_PORT|UDP_PORT|BROADCAST_PORT)\s*=\s*(\d+)")

# Files worth scanning: skip generated R/BuildConfig
_SKIP_RE = re.compile(r"(?:^|[\\/])[RB][A-Z]?\.java$|BuildConfig\.java$")

# Supported service type protocols (with or without .local[.] suffix or bare trailing dot)
_PROTO_RE = re.compile(r"\._(?:tcp|udp)(?:\.local)?\.?$", re.I)


def scan(sources_dir: Path, app_package: str) -> DiscoveryMechanism:
    """Return the best DiscoveryMechanism found in *sources_dir*."""
    java_files = [p for p in sources_dir.rglob("*.java") if not _SKIP_RE.search(str(p))]

    service_types: list[str] = []
    has_multicast = False
    has_datagram = False
    udp_port: int | None = None

    for path in java_files:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue

        # mDNS service type patterns (all five)
        for pat in (
            _NSD_DISCOVER_RE,
            _NSD_SET_TYPE_RE,
            _MDNS_CONST_RE,
            _JMDNS_CREATE_RE,
            _NSD_REGISTER_RE,
        ):
            for m in pat.finditer(text):
                stype = _normalize_service_type(m.group(1))
                if stype and stype not in service_types:
                    service_types.append(stype)

        if _MULTICAST_RE.search(text):
            has_multicast = True

        if _DATAGRAM_RE.search(text):
            has_datagram = True
            pm = _UDP_PORT_RE.search(text)
            if pm and udp_port is None:
                udp_port = int(pm.group(1))

    # ── pick best discovery type ───────────────────────────────────────────────
    if service_types:
        _LOGGER.info("discovery_scanner: zeroconf detected, service_types=%s", service_types)
        return DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type=service_types[0],
        )

    if has_multicast:
        _LOGGER.info("discovery_scanner: multicast lock detected — zeroconf (no service type)")
        hostname = _hostname_from_package(app_package)
        return DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            hostname_pattern=f"{hostname}*" if hostname else None,
        )

    if has_datagram:
        _LOGGER.info("discovery_scanner: UDP broadcast detected, port=%s", udp_port)
        return DiscoveryMechanism(
            type=DiscoveryType.UDP_BROADCAST,
            port=udp_port,
        )

    return DiscoveryMechanism(type=DiscoveryType.NONE)


# ── helpers ───────────────────────────────────────────────────────────────────


def _normalize_service_type(raw: str) -> str | None:
    """Ensure service type ends with '.local.' e.g. '_device._tcp.local.'."""
    raw = raw.strip()
    if not _PROTO_RE.search(raw):
        return None
    # Remove trailing dot before appending .local.
    if raw.endswith(".local."):
        return raw
    if raw.endswith(".local"):
        return raw + "."
    # "_device._tcp" or "_device._tcp."
    base = raw.rstrip(".")
    return base + ".local."


def _hostname_from_package(package: str) -> str:
    """'com.example.mydevice' → 'mydevice'"""
    parts = [
        p
        for p in package.split(".")
        if p and not p.startswith("com") and p not in ("net", "org", "io", "app")
    ]
    return parts[-1].lower() if parts else ""
