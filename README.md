# tls-auditor

Auditor defensivo de configuração **TLS/SSL**. Dado um `host:porta`, abre uma
conexão SSL e lista protocolos/versões suportadas, cifras (ciphers) e aponta
configurações fracas (SSLv3, TLS 1.0/1.1, cifras nulas/export, cert expirado).

> ⚠️ Ferramenta **educacional e defensiva**. Use apenas em sistemas de sua
> propriedade ou com autorização. Varrer hosts alheios pode ser ilegal.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/tls-auditor.git
cd tls-auditor
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/tls-auditor" ~/.local/bin/tls-auditor
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# audita o TLS padrao (porta 443)
tls-auditor example.com

# porta custom
tls-auditor example.com --port 8443
```

## Licença

MIT — veja `LICENSE`.
