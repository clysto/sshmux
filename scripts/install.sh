#!/bin/bash

BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

echo "Installing binaries to $BIN_DIR..."
cp sshpiper-plugin $BIN_DIR/sshpiper-plugin
cp sshmux-web $BIN_DIR/sshmux-web
cp sshpiperd $BIN_DIR/sshpiperd

echo "Installing systemd unit files to $SYSTEMD_DIR..."

if [ ! -f "$SYSTEMD_DIR/sshpiper.service" ]; then
    cp sshpiper.service $SYSTEMD_DIR/sshpiper.service
fi

if [ ! -f "$SYSTEMD_DIR/sshmux-web.service" ]; then
    cp sshmux-web.service $SYSTEMD_DIR/sshmux-web.service
fi

# 设置执行权限
chmod +x $BIN_DIR/sshpiper-plugin
chmod +x $BIN_DIR/sshmux-web
chmod +x $BIN_DIR/sshpiperd

echo "Installation complete."
