"""Núcleo do auditor TLS/SSL.

Implementa a lógica de detecção de configurações fracas de forma que
possa ser testada de forma isolada (sem necessidade de rede).
"""

import ssl


# Protocolos considerados inseguros e que não devem ser negociados.
DEPRECATED_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}

# Marcadores de cifras fracas / quebradas.
INSECURE_CIPHER_MARKERS = ("NULL", "RC4", "3DES", "EXPORT", "DES-CBC")


def classify_protocol(version: str) -> str:
    """Classifica uma string de versão de protocolo como fraca ou ok."""
    base = version.split()[0]
    if base in DEPRECATED_PROTOCOLS:
        return "weak"
    return "ok"


def is_weak_cipher(cipher_name: str) -> bool:
    """Detecta se um cipher é considerado fraco pelos marcadores conhecidos."""
    upper = cipher_name.upper()
    for marker in INSECURE_CIPHER_MARKERS:
        if marker in upper:
            return True
    return False


def split_weak_ciphers(ciphers) -> dict:
    """Recebe uma lista de nomes de ciphers e separa fracos de seguros."""
    weak = [c for c in ciphers if is_weak_cipher(c)]
    safe = [c for c in ciphers if not is_weak_cipher(c)]
    return {"weak": weak, "safe": safe}
