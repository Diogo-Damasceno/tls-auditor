"""Varredura real de um host:porta via SSL e análise de certificado."""

import datetime
import socket
import ssl


def is_cert_expired(not_after) -> bool:
    """Recebe a data de expiração do certificado e diz se já venceu.

    Aceita datetime ou string ISO; compara com o instante atual.
    """
    if isinstance(not_after, str):
        not_after = datetime.datetime.fromisoformat(not_after)
    return datetime.datetime.now() > not_after


def _open_ssl_socket(host: str, port: int, context, timeout: float):
    """Abre o socket TCP e envolve com TLS."""
    raw = socket.create_connection((host, port), timeout=timeout)
    return context.wrap_socket(raw, server_hostname=host)


def scan_host(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Conecta a host:porta, coleta protocolo, ciphers e validade do cert."""
    context = ssl.create_default_context()
    with _open_ssl_socket(host, port, context, timeout) as conn:
        protocol = conn.version()
        cipher = conn.cipher()[0]
        cert = conn.getpeercert()
        cert_expired = None
        if cert and "notAfter" in cert:
            exp = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(cert["notAfter"])
            )
            cert_expired = is_cert_expired(exp)

    return build_report(host, port, protocol, cipher, cert_expired)


def build_report(host, port, protocol, cipher, cert_expired) -> dict:
    """Monta o dicionário de resultado da varredura de forma testável."""
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "cipher": cipher,
        "cert_expired": cert_expired,
    }
