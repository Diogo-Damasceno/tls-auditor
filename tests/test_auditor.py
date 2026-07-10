"""Testes da lógica de detecção de cifras e protocolos fracos."""

from datetime import datetime, timedelta

from tls_auditor.auditor import (
    audit_cipher_list,
    classify_protocol,
    is_weak_cipher,
)
from tls_auditor.scanner import is_cert_expired


def test_classify_protocol_weak():
    assert classify_protocol("SSLv3") == "weak"
    assert classify_protocol("TLSv1") == "weak"
    assert classify_protocol("TLSv1.1") == "weak"


def test_classify_protocol_ok():
    assert classify_protocol("TLSv1.2") == "ok"
    assert classify_protocol("TLSv1.3") == "ok"


def test_is_weak_cipher_detects_markers():
    weak_samples = [
        "NULL-SHA",
        "RC4-MD5",
        "DES-CBC3-SHA",  # 3DES
        "EXP-RC4-MD5",   # EXPORT
    ]
    for c in weak_samples:
        assert is_weak_cipher(c) is True


def test_is_weak_cipher_safe():
    safe_samples = [
        "AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "CHACHA20-POLY1305",
    ]
    for c in safe_samples:
        assert is_weak_cipher(c) is False


def test_audit_cipher_list_separates():
    ciphers = ["AES256-GCM-SHA384", "RC4-MD5", "TLS_AES_256_GCM_SHA384", "DES-CBC3-SHA"]
    out = audit_cipher_list(ciphers)
    assert set(out["weak"]) == {"RC4-MD5", "DES-CBC3-SHA"}
    assert set(out["safe"]) == {"AES256-GCM-SHA384", "TLS_AES_256_GCM_SHA384"}


def test_is_cert_expired_future():
    future = datetime.now() + timedelta(days=30)
    assert is_cert_expired(future) is False


def test_is_cert_expired_past():
    past = datetime.now() - timedelta(days=30)
    assert is_cert_expired(past) is True


def test_is_cert_expired_string():
    past_str = (datetime.now() - timedelta(days=1)).isoformat()
    assert is_cert_expired(past_str) is True
