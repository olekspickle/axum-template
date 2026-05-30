#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Setup script: axum-template + Cloudflare Tunnel on Raspberry Pi
# Dockerless deployment with native cloudflared systemd service
# ============================================================
# Usage:
#   1. Cross-compile on dev machine:
#      just cross-build-pi   # or: cargo build --target aarch64-unknown-linux-gnu --release
#
#   2. Copy to Pi:
#      TARGET=target/aarch64-unknown-linux-gnu/release/axum-template
#      rsync -avz "$TARGET" config.toml static/ templates/ systemd/ pi@raspberrypi:~/deploy/
#
#   3. SSH into Pi and run:
#      ssh pi@raspberrypi
#      cd ~/deploy
#      bash setup.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP=axum-template
APP_USER=${APP_USER:-$APP}
APP_DIR=/opt/axum-template
BIN_PATH=/opt/axum-template/axum-template

CF_USER=cloudflared
CF_DIR=/opt/axum-template/cf
CF_BIN=$CF_DIR/cloudflared
CF_TUNNEL_NAME="${CF_TUNNEL_NAME:-$APP}"

ARCH="$(uname -m)"
case "$ARCH" in
    aarch64) CF_ARCH="arm64" ;;
    armv7l)  CF_ARCH="arm" ;;
    x86_64)  CF_ARCH="amd64" ;;
    *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

echo "============================================"
echo "axum-template + Cloudflare Tunnel Setup"
echo "Arch: $ARCH"
echo "============================================"

# --- cloudflared ---

if [ ! -f "$CF_BIN" ] && ! which cf &>/dev/null; then
    echo "[1/8] Downloading cloudflared ($CF_ARCH)..."
    sudo mkdir -p "$CF_DIR"
    # more here: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$CF_ARCH.tar.gz" \
        | sudo tar -xz -C "$CF_DIR" cloudflared
    sudo chmod +x "$CF_BIN"
    sudo ln -sf "$CF_BIN" /usr/local/bin/cloudflared
    sudo ln -sf "$CF_BIN" /usr/local/bin/cf
else
    sudo chmod +x "$CF_BIN"
    echo "[1/8] cloudflared already installed ($($CF_BIN --version))"
fi

echo "[2/8] Creating cloudflared system user..."
if ! id "$CF_USER" &>/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$CF_USER"
fi

echo "[3/8] Setting up cloudflared config..."
sudo mkdir -p "$CF_DIR"
if [ -f "$SCRIPT_DIR/cloudflared-config.yml" ]; then
    sudo cp "$SCRIPT_DIR/cloudflared-config.yml" "$CF_DIR/config.yml"
fi
sudo chown -R "$CF_USER:$CF_USER" "$CF_DIR"
sudo chmod 700 "$CF_DIR"

# --- axum-template ---

echo "[4/8] Creating axum-template system user..."
if ! id "$APP_USER" &>/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

echo "[5/8] Creating app directories..."
sudo mkdir -p "$APP_DIR"
sudo mkdir -p "$CF_DIR"

echo "[6/8] Installing binary and assets..."
if [ -f "$SCRIPT_DIR/axum-template" ]; then
    sudo cp "$SCRIPT_DIR/axum-template" "$BIN_PATH"
    sudo chmod +x "$BIN_PATH"
else
    echo "WARNING: axum-template binary not found — place it manually at $BIN_PATH"
fi

for dir in static templates; do
    if [ -d "$SCRIPT_DIR/$dir" ]; then
        sudo cp -r "$SCRIPT_DIR/$dir" "$APP_DIR/"
    fi
done

if [ -f "$SCRIPT_DIR/config.toml" ]; then
    sudo cp "$SCRIPT_DIR/config.toml" "$APP_DIR/config.toml"
fi

sudo chown -R "$APP_USER:$APP_USER" "$APP_DIR"

echo "[7/8] Setting up environment file..."
if [ ! -f "$APP_DIR/.env" ]; then
    read -sp "Enter ADMIN_PASSWORD: " ADMIN_PW
    echo
    echo "ADMIN_PASSWORD=$ADMIN_PW" | sudo tee "$APP_DIR/.env" > /dev/null
    sudo chmod 600 "$APP_DIR/.env"
    sudo chown root:root "$APP_DIR/.env"
else
    echo "$APP_DIR/.env already exists — edit it to set ADMIN_PASSWORD"
fi

echo "[8/8] Installing systemd services..."
INSTALL_DIR=/etc/systemd/system

for svc in axum-template.service cloudflared.service; do
    if [ -f "$SCRIPT_DIR/$svc" ]; then
        sudo cp "$SCRIPT_DIR/$svc" "$INSTALL_DIR/"
    else
        echo "  WARNING: $svc not found next to this script"
    fi
done

sudo systemctl daemon-reload
sudo systemctl enable axum-template.service
sudo systemctl enable cloudflared.service

echo ""
echo "============================================"
echo "Setup complete!"
echo ""
echo "Next steps:"
echo ""
echo "  1. Authenticate cloudflared (one-time):"
echo "       cf tunnel login"
echo "       # login saves cert.pem to ~/.cloudflared/"
echo "       sudo mkdir -p $CF_DIR"
echo "       sudo cp ~/.cloudflared/cert.pem $CF_DIR/"
echo "       sudo chown -R $CF_USER:$CF_USER $CF_DIR"
echo ""
echo "  2. Create and configure tunnel:"
echo "       sudo -u $CF_USER cf --config $CF_DIR/config.yml tunnel create $CF_TUNNEL_NAME"
echo "       sudo -u $CF_USER cf --config $CF_DIR/config.yml tunnel route dns $CF_TUNNEL_NAME your-domain.com"
echo ""
echo "  3. Edit $CF_DIR/config.yml:"
echo "       tunnel: $CF_TUNNEL_NAME"
echo "       credentials-file: $CF_DIR/$CF_TUNNEL_NAME.json"
echo "       ingress:"
echo "         - hostname: your-domain.com"
echo "           service: http://localhost:7777"
echo "         - service: http_status:404"
echo ""
echo "  4. Start services:"
echo "       sudo systemctl start axum-template.service"
echo "       sudo systemctl start cloudflared.service"
echo ""
echo "  5. Check status:"
echo "       sudo journalctl -u axum-template -f"
echo "       sudo journalctl -u cloudflared -f"
echo "============================================"
