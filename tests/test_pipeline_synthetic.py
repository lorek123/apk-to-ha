# SPDX-License-Identifier: MIT
"""F-2b — Synthetic fixture tests.

Exercises the pipeline against hand-crafted JADX output directories that
represent device protocols not covered by the R2-D2 fixture:

  - synthetic_govee: HTTP REST (Retrofit) + Zeroconf + API-key auth
  - synthetic_tuya:  Tuya SDK detection → early exit (P1-2)

No APK binary required — the scanner operates on the sources/ tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from engine.extraction.entity_classifier import classify
from engine.extraction.protocol_scanner import ProtocolScanner
from engine.ingestion import classifier, manifest_parser
from engine.ir.models import AuthType, DiscoveryType, Framework, TransportType

_FIXTURES = Path(__file__).parent / "fixtures"
_GOVEE_DIR = _FIXTURES / "synthetic_govee"


# ── Govee HTTP REST fixture ────────────────────────────────────────────────────


class TestGoveeHTTPRest:
    """synthetic_govee: Retrofit service + NsdManager discovery + Govee-API-Key header."""

    @pytest.fixture(scope="class")
    def scanner_result(self) -> Any:
        scanner = ProtocolScanner(_GOVEE_DIR)
        return scanner.scan("com.govee.home")

    def test_transport_is_http_rest(self, scanner_result: Any) -> None:
        transport, *_ = scanner_result
        assert transport.type == TransportType.HTTP_REST

    def test_discovery_is_zeroconf(self, scanner_result: Any) -> None:
        _, discovery, *_ = scanner_result
        assert discovery.type == DiscoveryType.ZEROCONF

    def test_auth_is_api_key(self, scanner_result: Any) -> None:
        _, _, auth, *_ = scanner_result
        assert auth.type == AuthType.API_KEY

    def test_retrofit_endpoints_extracted(self, scanner_result: Any) -> None:
        *_, commands, events = scanner_result
        cmd_names = [c.cmd for c in commands]
        assert any("govee/v1/dev/devList" in c for c in cmd_names)
        assert any("govee/v1/dev/control" in c for c in cmd_names)
        assert any("govee/v1/dev/devState" in c for c in cmd_names)

    def test_state_fields_from_serialized_name(self, scanner_result: Any) -> None:
        *_, state, commands, events = scanner_result
        field_names = {f.serialized_name for f in state.fields}
        # DeviceState.java has @SerializedName annotations
        assert "online" in field_names
        assert "brightness" in field_names
        assert "powerState" in field_names

    def test_entity_hints_on_govee(self, scanner_result: Any) -> None:
        transport, discovery, auth, state, commands, events = scanner_result
        from engine.ir.models import (
            Framework,
            ProtocolIR,
        )

        ir = ProtocolIR(
            apk_path="synthetic",
            package_name="com.govee.home",
            app_name="Govee Home",
            framework=Framework.NATIVE,
            transport=transport,
            discovery=discovery,
            auth=auth,
            state=state,
            commands=commands,
            events=events,
        )
        classified = classify(ir)
        assert classified is not None
        # All endpoints should have a hint after classification
        for ep in classified.commands:
            assert ep.entity_hint is not None


# ── Govee manifest parsing ─────────────────────────────────────────────────────


def test_govee_manifest_parse() -> None:
    info = manifest_parser.parse(_GOVEE_DIR)
    assert info.package_name == "com.govee.home"
    assert info.version_name == "5.6.01"
    assert "android.permission.INTERNET" in info.permissions


def test_govee_framework_classified_as_native() -> None:
    framework = classifier.classify(_GOVEE_DIR)
    assert framework == Framework.NATIVE


def test_govee_not_tuya() -> None:
    assert not classifier.check_tuya(_GOVEE_DIR, "com.govee.home")


# ── Tuya early-exit synthetic fixture ────────────────────────────────────────


def _make_tuya_tree(tmp_path: Path) -> Path:
    """Create a minimal source tree that looks like a Tuya SDK app."""
    pkg = tmp_path / "sources" / "com" / "thingclips" / "smart"
    pkg.mkdir(parents=True)
    (pkg / "TuyaApi.java").write_text("""
        package com.thingclips.smart;
        public class TuyaApi {
            // Tuya Smart SDK entry point
        }
    """)
    (tmp_path / "resources").mkdir()
    (tmp_path / "resources" / "AndroidManifest.xml").write_text("""
        <?xml version="1.0" encoding="utf-8"?>
        <manifest package="com.example.tuya_clone" android:versionName="1.0">
            <uses-permission android:name="android.permission.INTERNET" />
            <application android:label="SmartLife Clone" />
        </manifest>
    """)
    return tmp_path


def test_tuya_detection(tmp_path: Path) -> None:
    apk_dir = _make_tuya_tree(tmp_path)
    assert classifier.check_tuya(apk_dir, "com.example.tuya_clone")


def test_non_tuya_not_flagged(tmp_path: Path) -> None:
    pkg = tmp_path / "sources" / "com" / "example" / "myapp"
    pkg.mkdir(parents=True)
    (pkg / "MainActivity.java").write_text(
        "package com.example.myapp; public class MainActivity {}"
    )
    assert not classifier.check_tuya(tmp_path, "com.example.myapp")


# ── Tuya whitelabel detection ─────────────────────────────────────────────────
# These represent obfuscated whitelabel apps where the Tuya package dir is gone
# but other signals survive.


def _make_obfuscated_tree(tmp_path: Path) -> None:
    """Minimal decompiled APK with obfuscated package dirs (no com/tuya/ dir)."""
    pkg = tmp_path / "sources" / "com" / "mycompany" / "smartbulb"
    pkg.mkdir(parents=True)
    resources = tmp_path / "resources"
    resources.mkdir(exist_ok=True)


def test_whitelabel_detected_via_manifest(tmp_path: Path) -> None:
    """Tuya service name in AndroidManifest.xml flags the app even without SDK dirs."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "sources" / "com" / "mycompany" / "smartbulb" / "App.java").write_text(
        "package com.mycompany.smartbulb; public class App {}"
    )
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?>'
        '<manifest package="com.mycompany.smartbulb">'
        "<application>"
        '<service android:name="com.thingclips.smart.camera.middleware.MqttService"/>'
        "</application>"
        "</manifest>"
    )
    assert classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


def test_whitelabel_detected_via_import(tmp_path: Path) -> None:
    """import com.tuya.* in a Java file flags the app even without SDK dirs."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest package="com.mycompany.smartbulb"/>'
    )
    (tmp_path / "sources" / "com" / "mycompany" / "smartbulb" / "DeviceManager.java").write_text(
        "package com.mycompany.smartbulb;\n"
        "import com.tuya.smart.home.sdk.TuyaHomeSdk;\n"
        "public class DeviceManager {}"
    )
    assert classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


def test_whitelabel_detected_via_thingclips_import(tmp_path: Path) -> None:
    """import com.thingclips.* also triggers detection."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest package="com.mycompany.smartbulb"/>'
    )
    (tmp_path / "sources" / "com" / "mycompany" / "smartbulb" / "Sdk.java").write_text(
        "package com.mycompany.smartbulb;\n"
        "import com.thingclips.smart.sdk.api.ITuyaSmartDevice;\n"
        "public class Sdk {}"
    )
    assert classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


def test_whitelabel_detected_via_api_host_in_source(tmp_path: Path) -> None:
    """Tuya cloud API hostname in a string constant flags the app."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest package="com.mycompany.smartbulb"/>'
    )
    (tmp_path / "sources" / "com" / "mycompany" / "smartbulb" / "Config.java").write_text(
        "package com.mycompany.smartbulb;\n"
        "public class Config {\n"
        '    static final String API_HOST = "openapi.tuyacn.com";\n'
        "}"
    )
    assert classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


def test_whitelabel_detected_via_api_host_in_strings_xml(tmp_path: Path) -> None:
    """Tuya API hostname in strings.xml resource flags the app."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest package="com.mycompany.smartbulb"/>'
    )
    (tmp_path / "resources" / "strings.xml").write_text(
        '<?xml version="1.0"?><resources>'
        '<string name="tuya_host">openapi.tuyaeu.com</string>'
        "</resources>"
    )
    assert classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


def test_import_scan_reads_only_top_of_file(tmp_path: Path) -> None:
    """Import detection should NOT trigger on a Tuya string buried deep in a non-import context."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest package="com.mycompany.smartbulb"/>'
    )
    # 'import com.tuya.' buried far past 4 KB — should not be detected
    padding = "// " + "x" * 80 + "\n"
    deep_content = (
        "package com.mycompany.smartbulb;\n"
        + padding * 60  # >4 KB of padding
        + "import com.tuya.smart.SomeClass;  // too deep, not a real import\n"
        + "public class Hidden {}"
    )
    (tmp_path / "sources" / "com" / "mycompany" / "smartbulb" / "Hidden.java").write_text(
        deep_content
    )
    assert not classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


def test_clean_app_not_flagged(tmp_path: Path) -> None:
    """A non-Tuya whitelabel with no Tuya signals should not be flagged."""
    _make_obfuscated_tree(tmp_path)
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?>'
        '<manifest package="com.mycompany.smartbulb">'
        "<application>"
        '<service android:name="com.mycompany.smartbulb.SyncService"/>'
        "</application>"
        "</manifest>"
    )
    (tmp_path / "sources" / "com" / "mycompany" / "smartbulb" / "App.java").write_text(
        "package com.mycompany.smartbulb;\n"
        "import com.mycompany.smartbulb.internal.Client;\n"
        "public class App {}"
    )
    assert not classifier.check_tuya(tmp_path, "com.mycompany.smartbulb")


# ── Emitter context for Govee ─────────────────────────────────────────────────


def test_govee_emitter_context() -> None:
    """Govee's HTTP REST transport should produce a context with correct domain."""
    from engine.emitters.context import build
    from engine.ir.models import (
        Framework,
        ProtocolIR,
    )

    scanner = ProtocolScanner(_GOVEE_DIR)
    transport, discovery, auth, state, commands, events = scanner.scan("com.govee.home")

    ir = ProtocolIR(
        apk_path="synthetic",
        package_name="com.govee.home",
        app_name="Govee Home",
        framework=Framework.NATIVE,
        transport=transport,
        discovery=discovery,
        auth=auth,
        state=state,
        commands=commands,
        events=events,
    )
    ir = classify(ir)
    ctx = build(ir)

    assert ctx["domain"] == "home"
    assert ctx["class_prefix"] == "Home"
    assert ctx["sdk_package"] == "home_sdk"
    # HTTP REST device: sensors come from state fields
    assert len(ctx["sensors"]) > 0 or len(ctx["binary_sensors"]) > 0


# ── Cross-fixture: pipeline produces valid ruff-clean output ──────────────────


def test_govee_emitter_output_passes_ruff(tmp_path: Path) -> None:
    """Run emitter on Govee IR and verify output is ruff-clean."""
    import asyncio

    from engine.emitters import hacs_emitter, sdk_emitter
    from engine.emitters.context import build
    from engine.extraction.entity_classifier import classify
    from engine.ir.models import Framework, ProtocolIR
    from engine.validation import ruff_check

    scanner = ProtocolScanner(_GOVEE_DIR)
    transport, discovery, auth, state, commands, events = scanner.scan("com.govee.home")

    ir = ProtocolIR(
        apk_path="synthetic",
        package_name="com.govee.home",
        app_name="Govee Home",
        framework=Framework.NATIVE,
        transport=transport,
        discovery=discovery,
        auth=auth,
        state=state,
        commands=commands,
        events=events,
        extra=scanner.extra,
    )
    ir = classify(ir)
    ctx = build(ir)

    sdk_dir = sdk_emitter.emit(ctx, tmp_path)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)

    ruff_result = asyncio.run(ruff_check.check(hacs_dir))
    assert ruff_result.passed, f"ruff found {ruff_result.error_count} errors:\n" + "\n".join(
        f"  {f.file}:{f.line} [{f.code}] {f.message}" for f in ruff_result.findings
    )
