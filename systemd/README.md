# Webhook Intake — systemd deployment

[![Tests](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml/badge.svg)](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Certbot 5.4+](https://img.shields.io/badge/Certbot-5.4%2B-003A70)](https://certbot.eff.org/)

Leia este documento em [Português](README.pt-BR.md).

This directory contains the files that run Webhook Intake as a foreground process supervised by `systemd`. The project does not implement a separate Python daemon mode.

## Installation

The installer requires root, `systemd`, and Python 3.11 or later with `venv` support. Run it from a checkout installed at `/opt/webhook-intake`:

```bash
cd /opt/webhook-intake
sudo bash ./systemd/install.sh
sudoedit /etc/webhook-intake/config.ini
sudo systemctl enable --now webhook-intake.service
```

It creates the `whintake` service account, configuration and state directories, a virtual environment, and the systemd units. Existing configuration and profile files are preserved.

The repository has one configuration template: [`../config.ini.example`](../config.ini.example). The installer copies it to `/etc/webhook-intake/config.ini` and adjusts that copy to use system directories; the source template is never changed.

## Operation

```bash
sudo systemctl status webhook-intake.service
sudo journalctl -u webhook-intake.service -f
```

The unit permits writes only to `/var/lib/webhook-intake`. Provision TLS files before starting it. For a public IP certificate, first run the project's `--certbot-mode` with `/etc/webhook-intake/config.ini`, then enable renewal:

```bash
sudo systemctl enable --now webhook-intake-certbot-renew.timer
systemctl list-timers webhook-intake-certbot-renew.timer
```

The renewal unit assumes Certbot is installed at `/usr/bin/certbot`. Adjust [webhook-intake-certbot-renew.service](webhook-intake-certbot-renew.service) before installation if the system uses a different path.

For the full service, TLS, Basic Auth, and Certbot instructions, read the [main English README](../README.md#running-as-a-systemd-service).
