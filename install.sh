#!/usr/bin/env bash
# ScamStop install script. Runs from inside the standalone installer
# (scamstop-installer-VERSION-linux-x86_64.run), which carries Python, every
# library and the speech model. The only things fetched are your distribution's
# own packages for Redis and OpenSSL, from its usual mirrors.
#
# Works on Debian/Ubuntu, RHEL/Alma/Rocky/CentOS Stream, Fedora and openSUSE (ViciBox).
# Safe to run again to upgrade; settings in /etc/scamstop are kept.
#
#   SCAMSTOP_PORT=8443     panel port (HTTPS)
#   SCAMSTOP_NO_START=1    install but don't start the services
#   --uninstall            remove ScamStop (keeps /etc/scamstop and logs)
set -euo pipefail

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${SCAMSTOP_PORT:-8443}"
PREFIX=/opt/scamstop
ETC=/etc/scamstop
STATE=/var/lib/scamstop
MODEL="$PREFIX/models/sherpa-onnx-streaming-zipformer-en-2023-06-21"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v systemctl >/dev/null || die "systemd is required"

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now scamstop scamstop-panel 2>/dev/null || true
  rm -f /etc/systemd/system/scamstop.service /etc/systemd/system/scamstop-panel.service /usr/local/bin/scamstop
  systemctl daemon-reload
  rm -rf "$PREFIX"
  say "ScamStop removed. Your settings are still in $ETC and logs in /var/log/scamstop."
  exit 0
fi

[ -x "$BUNDLE/python/bin/python3" ] || die "installer is incomplete (no bundled Python)"
VER=$(cat "$BUNDLE/VERSION" 2>/dev/null || echo "?")
say "Installing ScamStop $VER"

# ---------------------------------------------------------------- system packages
if command -v apt-get >/dev/null; then
  PM=apt; export DEBIAN_FRONTEND=noninteractive
  pm_install() { apt-get install -y -q "$@" >/dev/null; }
  apt-get update -q >/dev/null || warn "apt-get update failed; trying with the current package lists"
elif command -v dnf >/dev/null; then
  PM=dnf; pm_install() { dnf install -y -q "$@" >/dev/null; }
elif command -v yum >/dev/null; then
  PM=yum; pm_install() { yum install -y -q "$@" >/dev/null; }
elif command -v zypper >/dev/null; then
  PM=zypper; pm_install() { zypper --non-interactive --quiet install "$@" >/dev/null; }
else
  die "no supported package manager (apt, dnf, yum, zypper)"
fi
command -v openssl >/dev/null || pm_install openssl || warn "couldn't install openssl; the panel will need --tls-cert/--tls-key"

redis_ok() { (command -v redis-cli >/dev/null && redis-cli ping 2>/dev/null | grep -q PONG) || \
             (command -v valkey-cli >/dev/null && valkey-cli ping 2>/dev/null | grep -q PONG); }
if ! redis_ok; then
  say "Installing Redis ($PM)"
  case "$PM" in
    apt) pm_install redis-server ;;
    zypper) pm_install redis ;;
    *) pm_install redis || pm_install valkey || { [ "$PM" != yum ] || { pm_install epel-release && pm_install redis; }; } ;;
  esac
  for svc in redis-server redis valkey; do
    systemctl enable --now "$svc" >/dev/null 2>&1 && break || true
  done
  if ! redis_ok && [ -f /etc/redis/default.conf.example ]; then   # openSUSE ships Redis as instances
    [ -f /etc/redis/default.conf ] || cp /etc/redis/default.conf.example /etc/redis/default.conf
    chown redis:redis /etc/redis/default.conf 2>/dev/null || true
    systemctl enable --now redis@default >/dev/null 2>&1 || true
  fi
  sleep 1
  redis_ok || die "Redis didn't start. Install and start Redis, then run the installer again."
fi

# ---------------------------------------------------------------- python, scamstop, model
mkdir -p "$PREFIX" "$ETC" "$STATE" /var/log/scamstop "$MODEL"
systemctl stop scamstop 2>/dev/null || true
say "Installing the bundled Python"
rm -rf "$PREFIX/python.new"
cp -a "$BUNDLE/python" "$PREFIX/python.new"
rm -rf "$PREFIX/python" "$PREFIX/venv"
mv "$PREFIX/python.new" "$PREFIX/python"
"$PREFIX/python/bin/python3" -m venv "$PREFIX/venv"
say "Installing ScamStop and its libraries (offline)"
"$PREFIX/venv/bin/pip" install -q --no-index --find-links "$BUNDLE/wheels" --upgrade "scamstop[live]==$VER"
ln -sf "$PREFIX/venv/bin/scamstop" /usr/local/bin/scamstop
say "Installing the speech model"
cp "$BUNDLE"/model/* "$MODEL/"

# ---------------------------------------------------------------- config
if [ ! -f "$ETC/config.yaml" ]; then
  say "Looking at this server"
  scamstop -c "$ETC/config.yaml" syscheck --write-config || true
fi

# ---------------------------------------------------------------- services
cat > /etc/systemd/system/scamstop.service <<EOF
[Unit]
Description=ScamStop: hang up on phone scams in real time
After=network-online.target redis-server.service redis.service rtpengine-daemon.service opensips.service kamailio.service asterisk.service freeswitch.service
Wants=network-online.target

[Service]
ExecStart=$PREFIX/venv/bin/scamstop -c $ETC/config.yaml run
Environment=PYTHONWARNINGS=ignore::DeprecationWarning
Nice=19
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/scamstop-panel.service <<EOF
[Unit]
Description=ScamStop control panel
After=network-online.target

[Service]
ExecStart=$PREFIX/venv/bin/scamstop -c $ETC/config.yaml ui --host 0.0.0.0 --port $PORT --tls auto --allow-restart
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable scamstop scamstop-panel >/dev/null 2>&1
if [ -z "${SCAMSTOP_NO_START:-}" ]; then
  systemctl restart scamstop-panel
  systemctl restart scamstop
fi

if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port="$PORT/tcp" && firewall-cmd -q --reload || true
elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT/tcp" >/dev/null || true
fi

for _ in $(seq 1 20); do [ -f "$ETC/panel-password" ] && break; sleep 0.5; done
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
say "ScamStop $VER is installed and watching calls (watch-only mode: nothing is hung up yet)."
echo
echo "   Open:      https://${IP:-this-server}:$PORT"
echo "   Password:  $(cat "$ETC/panel-password" 2>/dev/null || echo "in $ETC/panel-password once the panel starts")"
echo
echo "   Your browser will warn about the certificate the first time (it's self-signed); continue anyway."
echo "   Then open Setup: your phone system was detected and the settings are filled in."
echo
