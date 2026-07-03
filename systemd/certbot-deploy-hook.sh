#!/usr/bin/env bash
# Deploy a renewed Certbot certificate and reload the receiver.
set -euo pipefail

: "${RENEWED_LINEAGE:?Certbot did not provide RENEWED_LINEAGE}"

install -D -o @SERVICE_USER@ -g @SERVICE_GROUP@ -m 0644 \
  "$RENEWED_LINEAGE/fullchain.pem" \
  "@CONFIG_DIR@/tls/webhook-intake.crt"
install -D -o @SERVICE_USER@ -g @SERVICE_GROUP@ -m 0600 \
  "$RENEWED_LINEAGE/privkey.pem" \
  "@CONFIG_DIR@/tls/webhook-intake.key"

systemctl try-restart webhook-intake.service
