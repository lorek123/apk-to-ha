# SPDX-License-Identifier: MIT
"""Tests for streaming (camera/video WebSocket) detection in ProtocolScanner."""

from __future__ import annotations

from pathlib import Path

from engine.extraction.protocol_scanner import ProtocolScanner
from engine.ir.models import StreamingContract


def _make_sources(tmp_path: Path, files: dict[str, str]) -> Path:
    pkg = tmp_path / "sources" / "com" / "example"
    pkg.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (pkg / name).write_text(content)
    return tmp_path


def _scanner_with_sources(apk_dir: Path) -> ProtocolScanner:
    scanner = ProtocolScanner(apk_dir)
    scanner._app_package = "com.example"
    scanner._app_sources = list((apk_dir / "sources").rglob("*.java"))
    return scanner


# ── basic detection ───────────────────────────────────────────────────────────


def test_detect_streaming_basic(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "VideoSocketService.java": """
        public class VideoSocketService {
            private final int WEBSOCKET_PORT = 12121;
            void decodeFrame(byte[] data) {
                Bitmap bm = BitmapFactory.decodeByteArray(data, 0, data.length);
            }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    contract = scanner.extra.get("streaming_contract")
    assert isinstance(contract, StreamingContract)
    assert contract.port == 12121
    assert contract.frame_format == "jpeg"


def test_detect_streaming_stored_on_extra(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "CameraService.java": """
        public class CameraService {
            private final int WEBSOCKET_PORT = 9090;
            void handle(byte[] raw) { BitmapFactory.decodeByteArray(raw, 0, raw.length); }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert "streaming_contract" in scanner.extra
    assert scanner.extra["streaming_contract"].port == 9090


# ── keyword matching ──────────────────────────────────────────────────────────


def test_detect_streaming_camera_keyword(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "CameraSocketHandler.java": """
        public class CameraSocketHandler {
            private final int WEBSOCKET_PORT = 5555;
            void recv(byte[] d) { BitmapFactory.decodeByteArray(d, 0, d.length); }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert scanner.extra.get("streaming_contract") is not None


def test_detect_streaming_stream_keyword(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "LiveStreamManager.java": """
        public class LiveStreamManager {
            private final int VIDEO_PORT = 7777;
            void process(byte[] frame) { decodeByteArray(frame); }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert scanner.extra.get("streaming_contract") is not None


# ── negative cases ────────────────────────────────────────────────────────────


def test_detect_streaming_skips_non_video_class(tmp_path: Path) -> None:
    """A class with BitmapFactory but no video keyword in name → not detected."""
    apk_dir = _make_sources(
        tmp_path,
        {
            "ImageHelper.java": """
        public class ImageHelper {
            private final int WEBSOCKET_PORT = 12121;
            void decode(byte[] d) { BitmapFactory.decodeByteArray(d, 0, d.length); }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert "streaming_contract" not in scanner.extra


def test_detect_streaming_requires_bitmap_factory(tmp_path: Path) -> None:
    """A video-named class without BitmapFactory → not detected."""
    apk_dir = _make_sources(
        tmp_path,
        {
            "VideoSocketService.java": """
        public class VideoSocketService {
            private final int WEBSOCKET_PORT = 12121;
            void handleMessage(String msg) { /* text only */ }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert "streaming_contract" not in scanner.extra


def test_detect_streaming_requires_port_constant(tmp_path: Path) -> None:
    """A video-named class with BitmapFactory but no port constant → not detected."""
    apk_dir = _make_sources(
        tmp_path,
        {
            "VideoSocket.java": """
        public class VideoSocket {
            // port is passed from outside, no constant here
            void recv(byte[] d) { BitmapFactory.decodeByteArray(d, 0, d.length); }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert "streaming_contract" not in scanner.extra


def test_detect_streaming_empty_sources(tmp_path: Path) -> None:
    """No source files → no crash, no contract."""
    apk_dir = tmp_path
    (apk_dir / "sources").mkdir()
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    assert "streaming_contract" not in scanner.extra


# ── rotation extraction ───────────────────────────────────────────────────────


def test_detect_streaming_rotation_extracted(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "VideoSocketService.java": """
        public class VideoSocketService {
            private final int WEBSOCKET_PORT = 12121;
            void decode(byte[] d) {
                BitmapFactory.decodeByteArray(d, 0, d.length);
                matrix.postRotate(90.0f, cx, cy);
            }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    contract = scanner.extra.get("streaming_contract")
    assert contract is not None
    assert contract.rotate_degrees == 90


def test_detect_streaming_negative_rotation(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "VideoSocketService.java": """
        public class VideoSocketService {
            private final int WEBSOCKET_PORT = 12121;
            void decode(byte[] d) {
                BitmapFactory.decodeByteArray(d, 0, d.length);
                matrix.postRotate(-90.0f);
            }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    contract = scanner.extra.get("streaming_contract")
    assert contract is not None
    assert contract.rotate_degrees == -90


def test_detect_streaming_default_rotation_zero(tmp_path: Path) -> None:
    apk_dir = _make_sources(
        tmp_path,
        {
            "VideoSocket.java": """
        public class VideoSocket {
            private final int WEBSOCKET_PORT = 12121;
            void decode(byte[] d) { BitmapFactory.decodeByteArray(d, 0, d.length); }
        }
        """,
        },
    )
    scanner = _scanner_with_sources(apk_dir)
    scanner._detect_streaming()
    contract = scanner.extra.get("streaming_contract")
    assert contract is not None
    assert contract.rotate_degrees == 0


# ── via scan() ────────────────────────────────────────────────────────────────


def test_detect_streaming_via_scan(tmp_path: Path) -> None:
    """Streaming contract is populated when scan() is called end-to-end."""
    pkg = tmp_path / "sources" / "com" / "test"
    pkg.mkdir(parents=True)
    (tmp_path / "resources").mkdir()
    (tmp_path / "resources" / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?>'
        '<manifest package="com.test.app" android:versionName="1.0">'
        "<application/></manifest>"
    )
    (pkg / "VideoSocketService.java").write_text("""
    public class VideoSocketService {
        private final int WEBSOCKET_PORT = 12121;
        void decode(byte[] d) { BitmapFactory.decodeByteArray(d, 0, d.length); }
    }
    """)
    scanner = ProtocolScanner(tmp_path)
    scanner.scan("com.test.app")
    contract = scanner.extra.get("streaming_contract")
    assert isinstance(contract, StreamingContract)
    assert contract.port == 12121


# ── IR model ─────────────────────────────────────────────────────────────────


def test_streaming_contract_model_defaults() -> None:
    c = StreamingContract(port=12121)
    assert c.frame_format == "jpeg"
    assert c.rotate_degrees == 0


def test_streaming_contract_model_custom() -> None:
    c = StreamingContract(port=5000, frame_format="mjpeg", rotate_degrees=180)
    assert c.port == 5000
    assert c.frame_format == "mjpeg"
    assert c.rotate_degrees == 180
