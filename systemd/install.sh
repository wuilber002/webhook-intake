#!/usr/bin/env bash
# Install the local checkout as a systemd-managed Webhook Intake service.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APP_DIR=${APP_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}
CONFIG_DIR=${CONFIG_DIR:-/etc/webhook-intake}
STATE_DIR=${STATE_DIR:-/var/lib/webhook-intake}
HOOK_PATH=${HOOK_PATH:-/usr/local/libexec/webhook-intake-certbot-deploy-hook}
SERVICE_USER=${SERVICE_USER:-whintake}
SERVICE_GROUP=${SERVICE_GROUP:-whintake}
PYTHON_BIN=${PYTHON_BIN:-python3.11}

command -v "$PYTHON_BIN" >/dev/null || {
  echo "Required interpreter not found: $PYTHON_BIN" >&2
  exit 1
}
[[ -f "$APP_DIR/webhook.py" ]] || {
  echo "webhook.py was not found in APP_DIR: $APP_DIR" >&2
  exit 1
}

if ! getent group "$SERVICE_GROUP" >/dev/null; then
  groupadd --system "$SERVICE_GROUP"
fi
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" \
    --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR/profile.d"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR/tls"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$STATE_DIR/output"

if [[ ! -f "$CONFIG_DIR/config.ini" ]]; then
  install -o root -g "$SERVICE_GROUP" -m 0640 \
    "$APP_DIR/config.ini.example" "$CONFIG_DIR/config.ini"
  # The repository template uses relative paths for standalone execution.
  # Its system-wide copy uses the service state and configuration directories.
  sed -i \
    -e "s|^output_dir\s*=.*|output_dir = $STATE_DIR/output|" \
    -e "s|^profile_dir\s*=.*|profile_dir = $CONFIG_DIR/profile.d|" \
    -e "s|^basic_auth_password_file\s*=.*|basic_auth_password_file = $CONFIG_DIR/.faj383hfa|" \
    -e "s|^tls_cert_file\s*=.*|tls_cert_file = $CONFIG_DIR/tls/webhook-intake.crt|" \
    -e "s|^tls_key_file\s*=.*|tls_key_file = $CONFIG_DIR/tls/webhook-intake.key|" \
    "$CONFIG_DIR/config.ini"
  echo "Created $CONFIG_DIR/config.ini"
else
  echo "Kept existing $CONFIG_DIR/config.ini"
fi

for profile in "$APP_DIR"/profile.d/*.conf; do
  [[ -e "$profile" ]] || continue
  target="$CONFIG_DIR/profile.d/$(basename "$profile")"
  if [[ ! -e "$target" ]]; then
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 "$profile" "$target"
  fi
done

if [[ ! -x "$APP_DIR/.venv/bin/python" ]]; then
  "$PYTHON_BIN" -m venv "$APP_DIR/.venv"
fi
# The receiver only executes the virtual environment; keeping it root-owned
# prevents the network-facing service account from replacing its interpreter.
chown -R root:root "$APP_DIR/.venv"

render_template() {
  local source=$1 destination=$2 mode=$3
  sed -e "s|@APP_DIR@|$APP_DIR|g" \
      -e "s|@CONFIG_DIR@|$CONFIG_DIR|g" \
      -e "s|@STATE_DIR@|$STATE_DIR|g" \
      -e "s|@HOOK_PATH@|$HOOK_PATH|g" \
      -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
      -e "s|@SERVICE_GROUP@|$SERVICE_GROUP|g" \
      "$source" > "$destination"
  chmod "$mode" "$destination"
}

render_template "$SCRIPT_DIR/webhook-intake.service" \
  /etc/systemd/system/webhook-intake.service 0644
render_template "$SCRIPT_DIR/webhook-intake-certbot-renew.service" \
  /etc/systemd/system/webhook-intake-certbot-renew.service 0644
render_template "$SCRIPT_DIR/webhook-intake-certbot-renew.timer" \
  /etc/systemd/system/webhook-intake-certbot-renew.timer 0644
install -d -o root -g "$SERVICE_GROUP" -m 0750 "$(dirname "$HOOK_PATH")"
render_template "$SCRIPT_DIR/certbot-deploy-hook.sh" \
  "$HOOK_PATH" 0750
chown root:"$SERVICE_GROUP" "$HOOK_PATH"

systemctl daemon-reload
echo
echo "Review $CONFIG_DIR/config.ini and profiles in $CONFIG_DIR/profile.d/."
echo "Then start: systemctl enable --now webhook-intake.service"
echo "For Certbot IP certificates, run Certbot mode first and then enable:"
echo "  systemctl enable --now webhook-intake-certbot-renew.timer"
