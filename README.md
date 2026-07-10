# tls-auditor

Auditor defensivo de configuração **TLS/SSL**. Dado um `host:porta`, abre uma
conexão SSL e lista protocolos/versões suportadas, cifras (ciphers) e aponta
configurações fracas.

## Aviso ético

Esta ferramenta é **educacional e defensiva**. Use-a apenas em sistemas de sua
propriedade ou nos quais tenha autorização explícita para realizar testes de
segurança. Varrer hosts de terceiros sem permissão pode violar leis e políticas
de uso. O autor não se responsabiliza por uso indevido.

## Instalação

```bash
pip install -e .
```

Requer Python 3.10+ (apenas biblioteca padrão).

## Uso

```bash
tls-auditor example.com
tls-auditor example.com --port 8443
```

A saída mostra o protocolo negociado, o cipher e o estado de validade do
certificado, sinalizando configurações inseguras.

## O que é detectado como fraco

- Protocolos: **SSLv3**, **TLS 1.0**, **TLS 1.1**
- Cifras: **NULL**, **RC4**, **3DES**, **EXPORT**, **DES-CBC**
- Certificado **expirado**

## Testes

```bash
pip install pytest
pytest tests/
```

## Licença

MIT — Copyright (c) 2026 Diogo Damasceno. Veja `LICENSE`.
