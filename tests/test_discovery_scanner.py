# SPDX-License-Identifier: MIT
"""Tests for P5-7 discovery scanner and manifest/config_flow emission."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.discovery_scanner import (
    _hostname_from_package,
    _normalize_service_type,
    scan,
)
from engine.ir.models import DiscoveryType


# ── _normalize_service_type ───────────────────────────────────────────────────

def test_normalize_adds_local_suffix():
    assert _normalize_service_type("_device._tcp") == "_device._tcp.local."


def test_normalize_already_local():
    assert _normalize_service_type("_device._tcp.local.") == "_device._tcp.local."


def test_normalize_partial_local():
    assert _normalize_service_type("_device._tcp.local") == "_device._tcp.local."


def test_normalize_udp():
    assert _normalize_service_type("_device._udp") == "_device._udp.local."


def test_normalize_invalid_returns_none():
    assert _normalize_service_type("not_a_service_type") is None


def test_normalize_trailing_dot():
    assert _normalize_service_type("_device._tcp.") == "_device._tcp.local."


# ── _hostname_from_package ────────────────────────────────────────────────────

def test_hostname_from_package_simple():
    assert _hostname_from_package("com.example.mydevice") == "mydevice"


def test_hostname_from_package_strips_com():
    assert _hostname_from_package("com.example.device") == "device"


def test_hostname_from_package_empty():
    result = _hostname_from_package("com")
    assert isinstance(result, str)


# ── scan() ────────────────────────────────────────────────────────────────────

def _write_java(tmp_path: Path, content: str, name: str = "DeviceManager.java") -> Path:
    p = tmp_path / "sources" / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


_JAVA_NSD_DISCOVER = """\
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;

public class NsdHelper {
    public void startDiscovery(NsdManager nsdManager) {
        nsdManager.discoverServices("_mydevice._tcp", NsdManager.PROTOCOL_DNS_SD, listener);
    }
}
"""

_JAVA_NSD_SET_TYPE = """\
import android.net.nsd.NsdServiceInfo;

public class NsdRegistration {
    public NsdServiceInfo buildServiceInfo() {
        NsdServiceInfo serviceInfo = new NsdServiceInfo();
        serviceInfo.setServiceType("_lightbulb._tcp");
        serviceInfo.setServiceName("SmartLight");
        serviceInfo.setPort(8888);
        return serviceInfo;
    }
}
"""

_JAVA_JMDNS = """\
import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;

public class MdnsClient {
    public void register() throws Exception {
        JmDNS jmdns = JmDNS.create(addr, "hostname");
        ServiceInfo info = ServiceInfo.create("_thermostat._tcp.", "MyThermostat", 9000, "");
        jmdns.registerService(info);
    }
}
"""

_JAVA_MULTICAST = """\
import android.net.wifi.WifiManager;

public class NetworkHelper {
    WifiManager.MulticastLock multicastLock;

    public void enableMulticast(WifiManager wifi) {
        multicastLock = wifi.createMulticastLock("mdns");
        multicastLock.acquire();
    }
}
"""

_JAVA_UDP_BROADCAST = """\
import java.net.DatagramSocket;
import java.net.DatagramPacket;

public class UdpDiscovery {
    private static final int SERVER_PORT = 6445;

    public void discover() throws Exception {
        DatagramSocket socket = new DatagramSocket();
        DatagramPacket packet = new DatagramPacket(buf, buf.length, broadcast, SERVER_PORT);
        socket.send(packet);
    }
}
"""

_JAVA_MDNS_CONST = """\
public class Constants {
    public static final String SERVICE_TYPE = "_smartplug._tcp";
}
"""


def test_scan_nsd_discover_returns_zeroconf(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_NSD_DISCOVER)
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.ZEROCONF


def test_scan_nsd_discover_service_type(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_NSD_DISCOVER)
    result = scan(tmp_path / "sources", "com.example")
    assert result.service_type == "_mydevice._tcp.local."


def test_scan_set_service_type(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_NSD_SET_TYPE)
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.ZEROCONF
    assert result.service_type == "_lightbulb._tcp.local."


def test_scan_jmdns(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_JMDNS)
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.ZEROCONF
    assert "_thermostat._tcp" in (result.service_type or "")


def test_scan_multicast_lock_zeroconf(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_MULTICAST)
    result = scan(tmp_path / "sources", "com.example.mylight")
    assert result.type == DiscoveryType.ZEROCONF


def test_scan_multicast_no_service_type(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_MULTICAST)
    result = scan(tmp_path / "sources", "com.example.mylight")
    assert result.service_type is None


def test_scan_multicast_hostname_pattern(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_MULTICAST)
    result = scan(tmp_path / "sources", "com.example.mylight")
    assert result.hostname_pattern is not None
    assert result.hostname_pattern.endswith("*")


def test_scan_udp_broadcast(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_UDP_BROADCAST)
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.UDP_BROADCAST


def test_scan_udp_broadcast_port(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_UDP_BROADCAST)
    result = scan(tmp_path / "sources", "com.example")
    assert result.port == 6445


def test_scan_mdns_const(tmp_path):
    _write_java(tmp_path / "sources", _JAVA_MDNS_CONST, "Constants.java")
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.ZEROCONF
    assert "_smartplug._tcp" in (result.service_type or "")


def test_scan_no_discovery(tmp_path):
    _write_java(tmp_path / "sources", "public class Foo { }", "Foo.java")
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.NONE


def test_scan_zeroconf_wins_over_udp(tmp_path):
    # File has both NSD and UDP — zeroconf takes priority
    combined = _JAVA_NSD_SET_TYPE + "\n" + _JAVA_UDP_BROADCAST
    _write_java(tmp_path / "sources", combined)
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.ZEROCONF


def test_scan_empty_sources_dir(tmp_path):
    (tmp_path / "sources").mkdir()
    result = scan(tmp_path / "sources", "com.example")
    assert result.type == DiscoveryType.NONE
