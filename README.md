# Webhook Intake

[![Tests](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml/badge.svg)](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml)

Leia este documento em [Português](README.pt-BR.md).

A lightweight HTTP server that receives webhook messages and stores them locally. It does not cryptographically validate the sender; place it behind a trusted network or reverse proxy (or add authentication at the proxy) before exposing it to the Internet.

## Legal notice

This material is provided as is, without express or implied warranties, including warranties of fitness for a particular purpose, availability, security, continuity, or compatibility.

There is no commitment to support, service-level agreement, maintenance, or future development. Use, modification, and redistribution are entirely the user's responsibility and at the user's own risk.

Before any use, users are responsible for validating behavior, security, compliance, and operational suitability for their environment. Authors and contributors are not liable for losses, damages, service interruptions, incorrect configurations, or unintended impacts arising from use of this material.

## Navigation

[Português](README.pt-BR.md) · [Server configuration template](config.ini.example) · [Profiles](profile.d/) · [Example profile](profile.d/profile.conf.example) · [Webhook code](webhook.py) · [Tests](tests/) · [CI](.github/workflows/tests.yml) · [License](LICENSE)

## Requirements and startup

Python 3.11 or later is required. There are no external Python dependencies. OpenSSL is required only when generating a self-signed TLS certificate. Create a local configuration before starting:

```bash
cp config.ini.example config.ini
python3 webhook.py --config config.ini
```

The endpoint is `POST /webhook` and the health check is `GET /healthz`. The supplied [config.ini.example](config.ini.example) listens only on `127.0.0.1:1604` and writes to `./output/`. Copy it to `config.ini` and expose another address only behind a trusted firewall or reverse proxy.

To print every delivery to the terminal, including the selected profile, run:

```bash
python3 webhook.py --config config.ini --debug
```

Host and port can also be overridden: `--host 0.0.0.0 --port 1604`.

## HTTPS

Direct HTTPS is optional. Enable it in the local `config.ini` and provide an existing certificate and key:

```ini
tls_enabled = true
tls_cert_file = /etc/webhook-intake/fullchain.pem
tls_key_file = /etc/webhook-intake/privkey.pem
```

The server then listens at `https://host:port/webhook` and requires TLS 1.2 or later. Keep private-key paths outside the repository.

For development or a controlled internal environment, the script can create its own certificate on first startup:

```ini
tls_enabled = true
tls_self_signed = true
tls_cert_file = ./tls/webhook-intake.crt
tls_key_file = ./tls/webhook-intake.key
tls_self_signed_common_name = localhost
tls_self_signed_days = 365
```

Self-signed certificates require [OpenSSL](https://www.openssl.org/) and are not trusted by clients by default. For a local test, use `curl -k https://127.0.0.1:1604/webhook ...`; do not use `-k` in production. For public services, use a certificate issued by a trusted authority or terminate TLS at a trusted reverse proxy.

### Public IP certificate with Certbot

If a sender requires a publicly trusted certificate but connects to a public IP address instead of a hostname, use the special Certbot mode. It requires Certbot 5.4 or later, a globally routable static IP, and inbound TCP/80 available while Certbot performs standalone ACME validation:

```bash
sudo python3 webhook.py --config config.ini --certbot-mode \
  --certbot-ip 198.51.100.10 \
  --certbot-email admin@example.com
```

The script explains the operation and asks for confirmation before it contacts the CA. On success it copies the certificate and private key into `./tls/`, configures `config.ini` to enable HTTPS, and exits without starting the webhook. Use `--certbot-staging` for an initial dry run; its certificate is intentionally not publicly trusted. `--certbot-yes` is available only for a deliberate non-interactive invocation.

IP certificates are short-lived. Set up Certbot renewal and restart the webhook after renewal so that it loads the replacement certificate. The generated `tls/` directory is ignored by Git.

## Local usage

From the repository root, start the receiver with debug output:

```bash
python3 webhook.py --config config.ini --debug
```

In a second terminal, send a test message:

```bash
curl -i http://127.0.0.1:1604/webhook \
  -H 'Content-Type: application/json' \
  -d '{"title":"Local test","severity":"CRITICAL","body":"hello"}'
```

With `tls_enabled = true`, use `https://` instead. Add `-k` only when testing a self-signed certificate.

The matching profile writes under `output/` by default. Stop the receiver with `Ctrl+C`.

## Expected message flow

```mermaid
flowchart LR
    Sender["Webhook-enabled\nmessage sender"] -->|"POST /webhook"| Receiver["Webhook Intake"]
    Receiver --> Check{"Valid path, size,\nand Content-Length?"}
    Check -->|No| Reject["HTTP error response"]
    Check -->|Yes| Match["Parse JSON and match\nsource + profile rules"]
    Match -->|"No normal match"| Fallback["catch_all profile"]
    Match -->|"One or more matches"| Render["Render raw, text,\nJSONL, or YAML"]
    Fallback --> Render
    Render --> Delivery{"Profile delivery"}
    Delivery -->|file| File["Append to output file"]
    Delivery -->|fifo| Pipe["Write to named pipe\nwithout blocking"]
    Delivery -->|both| File
    Delivery -->|both| Pipe
    File --> Consumers["Local consumers or\nother integrations"]
    Pipe --> Consumers
    Delivery --> Accepted["HTTP 202 Accepted"]
```

For a FIFO profile with `fifo_on_unavailable = fail`, a required FIFO delivery failure returns HTTP 503 instead of HTTP 202, allowing a sender that supports retries to try again.

## Profiles

Profiles are evaluated in file order. All `match` rules in one profile must match. A message can be written by more than one profile; set `stop_after_match = true` to stop after that profile. A profile with `catch_all = true` is used only when no regular profile matches.

A rule uses a dotted field path and a value. Values can use `equals`, `contains`, `regex`, or `value` (a short form for exact equality). Messages whose `body` contains JSON text also support paths such as `body.metadata.severity`.

Each profile supports:

- `file`: path relative to `output_dir`, or an absolute path. The output directory is created when needed; when omitted, it defaults to `./output` next to the configuration file.
- `delivery`: `file` (default), `fifo`, or `both`.
- `fifo_path`: FIFO path for `fifo` and `both` delivery.
- `fifo_on_unavailable`: `warn` (default) or `fail`.
- `format`: `raw`, `text`, `jsonl`, or `yaml`.
- `text_template`: only for `text`; supports message fields such as `{title}` or `{body}`. Missing fields are rendered as empty strings.

`raw` preserves the received body. `jsonl` writes one compact JSON value per line and requires a `.jsonl` or `.ndjson` file; standard `.json` documents are intentionally unsupported. `yaml` produces simple YAML without an external library and requires a `.yaml` or `.yml` file. For a non-JSON body, structured formats store `{received_at, content_type, raw}`.

## The `profile.d` directory

`config.ini` contains server settings only and declares `profile_dir = ./profile.d`. At startup, every `*.conf` file in that directory is loaded in alphabetical order. Files with no `[profile:name]` section, invalid syntax, or invalid profile settings are ignored with a warning; the server keeps running. Profiles in `config.ini` are rejected to keep configuration organized.

Use [profile.d/profile.conf.example](profile.d/profile.conf.example) as a reference. It documents every available option and uses dummy values. Copy it to a `.conf` file, set `enabled = true`, and adjust its values to activate it.

## File or FIFO delivery

Each profile can select `delivery = file` (default), `fifo`, or `both`. For `fifo` and `both`, set `fifo_path`; the named pipe is created automatically. FIFO writes are non-blocking, so a missing consumer never freezes the HTTP endpoint.

Use `fifo_on_unavailable = warn` (default) to log the event in debug mode and continue, or `fail` to return HTTP 503 so that the sender can retry. Messages larger than the FIFO atomic limit (`PIPE_BUF`) are rejected to avoid partial delivery. `both` is recommended when the file is also needed as a reliable history.

## File rotation

File-based profiles can rotate output by size before a new delivery would exceed the configured limit:

```ini
rotate_max_bytes = 10485760
rotate_keep = 10
rotation_mode = rename
```

`rotate_max_bytes` is measured in bytes; `0` disables rotation. `rotate_keep` controls the number of archived files retained. Archives are named beside the active file, for example `critical.20260703T143000Z.001.jsonl`.

Two rotation modes are available:

- `rename` (recommended): renames the active file to an archive and creates a new active file on the next write. This preserves the old inode so correct consumers can finish reading it. Consumers should follow the filename (`tail -F`) or detect inode changes and reopen the active file.
- `copytruncate`: copies the active file to an archive, then truncates that same file. This favors legacy consumers using `tail -f` on a fixed path, but a slow consumer can miss data that it had not read before truncation. Do not use it when exactly-once consumption is required.

Rotation is performed under the webhook write lock, so the webhook's own writes do not interleave with the rotation. For consumers that need immediate delivery, use `delivery = both` and treat the rotated JSONL file as durable history.

## Source identification

In addition to content rules, a profile can restrict the network source of a message:

```ini
[profile:trusted-source]
file = messages.raw
format = raw
origin_cidr = 10.0.0.0/24
```

Use `origin` for an exact IP, `origin_cidr` for a CIDR range, or `origin_regex` for a regular expression. All profile criteria must match. The default source is the IP that opened the connection. If a trusted reverse proxy is in front of the webhook, set `trust_forwarded_for = true` to use the first IP in `X-Forwarded-For`; do not enable it when exposing the service directly.

## Send example

```bash
curl -i http://127.0.0.1:1604/webhook \
  -H 'Content-Type: application/json' \
  -d '{"title":"High CPU","severity":"CRITICAL","body":"instance vm-01"}'
```

## Tests

The `tests/` directory contains automated tests for configuration loading, profiles, source filters, file writes, FIFO delivery, and the HTTP endpoint. They help prevent regressions when changing the webhook or its profiles.

```bash
python3 -m unittest discover -s tests -v
```

Running the test file directly also works:

```bash
python3 tests/test_webhook.py
```

## GitHub

The repository includes `.gitignore` to keep received messages, caches, and local environments out of version control, as well as a workflow at `.github/workflows/tests.yml` that runs tests on every push and pull request.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
