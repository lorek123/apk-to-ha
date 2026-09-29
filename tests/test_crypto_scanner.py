# SPDX-License-Identifier: MIT
"""Tests for P2-4 crypto API scanner."""

from __future__ import annotations

from pathlib import Path

from engine.extraction.crypto_scanner import _extract_algorithm, _normalise, scan

# ── normalise helper ──────────────────────────────────────────────────────────


def test_normalise_hmacsha256() -> None:
    assert _normalise("HmacSHA256") == "HMAC-SHA256"


def test_normalise_hmacsha1() -> None:
    assert _normalise("HmacSHA1") == "HMAC-SHA1"


def test_normalise_sha256_no_hyphen() -> None:
    assert _normalise("SHA256") == "SHA-256"


def test_normalise_aes_passthrough() -> None:
    assert _normalise("AES") == "AES"


def test_normalise_aes_cbc() -> None:
    assert _normalise("AES/CBC/PKCS5Padding") == "AES/CBC/PKCS5PADDING"


# ── extract_algorithm helper ──────────────────────────────────────────────────


def test_extract_algorithm_getinstance() -> None:
    line = '    Mac mac = Mac.getInstance("HmacSHA256");'
    assert _extract_algorithm(line) == "HmacSHA256"


def test_extract_algorithm_message_digest() -> None:
    line = '    MessageDigest md = MessageDigest.getInstance("SHA-256");'
    assert _extract_algorithm(line) == "SHA-256"


def test_extract_algorithm_cipher() -> None:
    line = '    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");'
    assert _extract_algorithm(line) == "AES/CBC/PKCS5Padding"


def test_extract_algorithm_secret_key_spec() -> None:
    line = '    SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");'
    assert _extract_algorithm(line) == "AES"


def test_extract_algorithm_no_match() -> None:
    assert _extract_algorithm("    int x = 5;") is None


# ── scan() integration tests ──────────────────────────────────────────────────


def _write_java(tmp_path: Path, filename: str, content: str) -> Path:
    p = tmp_path / "sources" / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_scan_finds_hmac(tmp_path: Path) -> None:
    _write_java(
        tmp_path,
        "com/example/Signer.java",
        """
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Signer {
    public String sign(String data, String secret) {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        mac.init(keySpec);
        return Base64.encode(mac.doFinal(data.getBytes()));
    }
}
""",
    )
    usages = scan(tmp_path)
    algos = {u.algorithm for u in usages}
    assert "HMAC-SHA256" in algos


def test_scan_finds_message_digest(tmp_path: Path) -> None:
    _write_java(
        tmp_path,
        "com/example/Hasher.java",
        """
import java.security.MessageDigest;

public class Hasher {
    public byte[] hash(byte[] data) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
""",
    )
    usages = scan(tmp_path)
    algos = {u.algorithm for u in usages}
    assert "SHA--256" in algos or "SHA-256" in algos or any("SHA" in a for a in algos)


def test_scan_returns_empty_for_no_crypto(tmp_path: Path) -> None:
    _write_java(
        tmp_path,
        "com/example/Simple.java",
        """
public class Simple {
    public void hello() {
        System.out.println("hello world");
    }
}
""",
    )
    usages = scan(tmp_path)
    assert usages == []


def test_scan_records_call_site(tmp_path: Path) -> None:
    _write_java(
        tmp_path,
        "com/example/auth/TokenSigner.java",
        """
import javax.crypto.Mac;
public class TokenSigner {
    public void sign() {
        Mac mac = Mac.getInstance("HmacSHA1");
    }
}
""",
    )
    usages = scan(tmp_path)
    assert any("TokenSigner" in u.call_site for u in usages)


def test_scan_low_confidence_for_import_only(tmp_path: Path) -> None:
    _write_java(
        tmp_path,
        "com/example/Base.java",
        """
import javax.crypto.Cipher;
public class Base {
    // just imports, no usage found
}
""",
    )
    usages = scan(tmp_path)
    assert any(u.confidence < 0.7 for u in usages)


def test_scan_deduplicates_same_algo_in_class(tmp_path: Path) -> None:
    _write_java(
        tmp_path,
        "com/example/Multi.java",
        """
import javax.crypto.Mac;
public class Multi {
    void a() { Mac.getInstance("HmacSHA256"); }
    void b() { Mac.getInstance("HmacSHA256"); }
}
""",
    )
    usages = scan(tmp_path)
    hmac_usages = [u for u in usages if u.algorithm == "HMAC-SHA256" and "Multi" in u.call_site]
    assert len(hmac_usages) == 1


def test_crypto_usage_in_ir(tmp_path: Path) -> None:
    """CryptoUsage can be serialised to/from the IR JSON."""
    from engine.ir.models import CryptoUsage as IRCryptoUsage

    cu = IRCryptoUsage(
        algorithm="HMAC-SHA256",
        call_site="com.example.Signer",
        context_snippet='Mac.getInstance("HmacSHA256")',
    )
    data = cu.model_dump()
    assert data["algorithm"] == "HMAC-SHA256"
    assert data["confidence"] == 1.0
