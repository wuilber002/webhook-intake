# Webhook Intake — implantação com systemd

[![Tests](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml/badge.svg)](https://github.com/wuilber002/webhook-intake/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Certbot 5.4+](https://img.shields.io/badge/Certbot-5.4%2B-003A70)](https://certbot.eff.org/)

Read this document in [English](README.md).

Este diretório contém os arquivos para executar o Webhook Intake como processo em primeiro plano supervisionado pelo `systemd`. O projeto não implementa um modo daemon separado no Python.

## Instalação

O instalador exige root, `systemd` e Python 3.11 ou superior com suporte a `venv`. Execute-o em um checkout instalado em `/opt/webhook-intake`:

```bash
cd /opt/webhook-intake
sudo bash ./systemd/install.sh
sudoedit /etc/webhook-intake/config.ini
sudo systemctl enable --now webhook-intake.service
```

Ele cria a conta de serviço `whintake`, os diretórios de configuração e estado, o ambiente virtual e as units do systemd. Arquivos de configuração e perfis já existentes são preservados.

O repositório tem um único modelo de configuração: [`../config.ini.example`](../config.ini.example). O instalador o copia para `/etc/webhook-intake/config.ini` e ajusta essa cópia para usar os diretórios do sistema; o modelo-fonte nunca é alterado.

## Operação

```bash
sudo systemctl status webhook-intake.service
sudo journalctl -u webhook-intake.service -f
```

A unit permite escrita somente em `/var/lib/webhook-intake`. Provisione arquivos TLS antes de iniciá-la. Para um certificado de IP público, execute primeiro o `--certbot-mode` do projeto usando `/etc/webhook-intake/config.ini` e, depois, habilite a renovação:

```bash
sudo systemctl enable --now webhook-intake-certbot-renew.timer
systemctl list-timers webhook-intake-certbot-renew.timer
```

A unit de renovação pressupõe que o Certbot esteja em `/usr/bin/certbot`. Altere [webhook-intake-certbot-renew.service](webhook-intake-certbot-renew.service) antes da instalação se o sistema usar outro caminho.

Para as instruções completas do serviço, TLS, Basic Auth e Certbot, leia o [README principal em português](../README.pt-BR.md#execução-como-serviço-systemd).
