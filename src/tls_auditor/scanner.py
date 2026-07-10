"""Varredura real de um host:porta via SSL e análise de certificado."""

import datetime
import ssl


def is_cert_expired(not_after) -> bool:
    """Recebe a data de expiração do certificado e diz se já venceu.

    Aceita datetime ou string ISO; compara com o instante atual.
    """
    if isinstance(not_after, str):
        not_after = datetime.datetime.fromisoformat(not_after)
    return datetime.datetime.now() > not_after


def scan_host(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Conecta a host:porta, coleta protocolo, ciphers e validade do cert."""
    context = ssl.create_default_context()
    result = {"host": host, "port": port, "protocol": None,
              "cipher": None, "cert_expired": None}

    with socket_create(host, port, context, timeout) as conn:
        result["protocol"] = conn.version()
        result["cipher"] = conn.cipher()[0]
        cert = conn.getpeercert()
        if cert and "notAfter" in cert:
            not_after = ssl.cert_time_to_seconds(cert["notAfter"])
            exp = datetime.datetime.fromtimestamp(not_after)
            result["cert_expired"] = is_cert_expired(exp)

    return result


def socket_create(host, port, context, timeout):
    import socket
    raw = socket.create_connection((host, port), timeout=timeout)
    return context.wrap_socket(raw, server_hostname=host)
