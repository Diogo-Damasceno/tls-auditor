"""Interface de linha de comando do tls-auditor."""

import argparse
import sys

from .auditor import audit_cipher_list, classify_protocol, is_weak_cipher
from .scanner import is_cert_expired, scan_host


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-auditor",
        description="Auditor defensivo de configuração TLS/SSL",
    )
    parser.add_argument("host", help="Host alvo (ex.: example.com)")
    parser.add_argument("--port", type=int, default=443, help="Porta (padrão 443)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    scan = scan_host(args.host, args.port)
    print(f"Host: {scan['host']}:{scan['port']}")
    print(f"Protocolo: {scan['protocol']}")
    print(f"Cipher: {scan['cipher']}")
    if scan["cert_expired"]:
        print("AVISO: certificado expirado")
    else:
        print("Certificado dentro da validade")
    return 0


if __name__ == "__main__":
    sys.exit(main())
