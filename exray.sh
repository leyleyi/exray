#!/bin/bash
# =========================================================
# EXRAY v1.0 (Stable)
# Powered by Leyi
# Xray Reality / VLESS / Trojan / Shadowsocks / Relay
# =========================================================

set -e

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# ---------- Paths ----------
XRAY_BIN="/usr/local/bin/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
SCRIPT_PATH="/usr/local/bin/exray"

# =========================================================
# Check
# =========================================================
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}请使用 root 权限运行${PLAIN}" && exit 1
}

check_sys() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}无法识别系统${PLAIN}"
        exit 1
    fi
}

# =========================================================
# Utils
# =========================================================
ip() {
    curl -s --max-time 5 https://api.ipify.org || curl -s --max-time 5 ifconfig.me
}

port() {
    shuf -i 10000-65535 -n1 2>/dev/null || echo $((RANDOM % 55536 + 10000))
}

uuid() {
    cat /proc/sys/kernel/random/uuid
}

# =========================================================
# Dependencies
# =========================================================
deps() {
    echo -e "${BLUE}安装系统依赖...${PLAIN}"
    case "$OS" in
        ubuntu|debian)
            apt update -y
            apt install -y curl wget jq unzip openssl ca-certificates
            ;;
        alpine)
            apk update
            apk add curl wget jq unzip openssl ca-certificates bash
            ;;
        centos|rhel|fedora)
            yum install -y curl wget jq unzip openssl ca-certificates
            ;;
    esac
}

# =========================================================
# Install Xray
# =========================================================
install_xray() {
    mkdir -p /usr/local/etc/xray

    if [ -x "$XRAY_BIN" ]; then
        echo -e "${YELLOW}Xray 已存在${PLAIN}"
        return
    fi

    read -rp "Github 代理(可空): " GITHUB_PROXY
    GITHUB_PROXY=$(echo "$GITHUB_PROXY" | xargs)
    [ -n "$GITHUB_PROXY" ] && [[ ! "$GITHUB_PROXY" =~ /$ ]] && GITHUB_PROXY="${GITHUB_PROXY}/"

    VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    [ -z "$VER" ] && echo -e "${RED}获取版本失败${PLAIN}" && exit 1

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) A=64 ;;
        aarch64) A=arm64-v8a ;;
        *) echo -e "${RED}不支持架构${PLAIN}"; exit 1 ;;
    esac

    TMP=$(mktemp -d)
    URL="https://github.com/XTLS/Xray-core/releases/download/$VER/Xray-linux-$A.zip"

    wget -qO "$TMP/xray.zip" "${GITHUB_PROXY}${URL}" || exit 1
    unzip -q "$TMP/xray.zip" -d "$TMP"
    install -m755 "$TMP/xray" "$XRAY_BIN"
    rm -rf "$TMP"

    echo -e "${GREEN}Xray 安装完成${PLAIN}"
}

# =========================================================
# Service
# =========================================================
service_start() {
    if [ "$OS" = "alpine" ]; then
cat >/etc/init.d/xray <<'EOF'
#!/sbin/openrc-run
name="xray"
command="/usr/local/bin/xray"
command_args="run -c /usr/local/etc/xray/config.json"
command_background="yes"
pidfile="/run/xray.pid"
EOF
        chmod +x /etc/init.d/xray
        rc-update add xray default
        rc-service xray start
    else
cat >/etc/systemd/system/xray.service <<EOF
[Unit]
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable xray --now
    fi
}

service_restart() {
    [ "$OS" = "alpine" ] && rc-service xray restart || systemctl restart xray
}

# =========================================================
# Shadowsocks Method
# =========================================================
choose_ss_method() {
    echo "1) 2022-blake3-aes-128-gcm (推荐)"
    echo "2) chacha20-ietf-poly1305"
    read -rp "选择 [1-2]: " c
    case "$c" in
        2) echo "chacha20-ietf-poly1305" ;;
        *) echo "2022-blake3-aes-128-gcm" ;;
    esac
}

# =========================================================
# Mode 1: VLESS Reality Vision
# =========================================================
mode_vless() {
    read -rp "备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)

    KEYS=$($XRAY_BIN x25519)
    PRI=$(echo "$KEYS" | awk '/PrivateKey/ {print $2}')
    PBK=$(echo "$KEYS" | awk '/PublicKey/ {print $2}')
    SID=$(openssl rand -hex 4)

cat >"$CONFIG_FILE"<<EOF
{
  "inbounds":[{
    "port":$PORT,
    "protocol":"vless",
    "settings":{
      "clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],
      "decryption":"none"
    },
    "streamSettings":{
      "network":"tcp",
      "security":"reality",
      "realitySettings":{
        "dest":"addons.mozilla.org:443",
        "serverNames":["addons.mozilla.org"],
        "privateKey":"$PRI",
        "shortIds":["$SID"],
        "fingerprint":"chrome",
        "xver":0
      }
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF

    echo -e "${GREEN}配置完成${PLAIN}"
    echo "vless://$UUID@$(ip):$PORT?security=reality&encryption=none&pbk=$PBK&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID#$REMARK"
}

# =========================================================
# Mode 2: Shadowsocks
# =========================================================
mode_ss() {
    read -rp "备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    METHOD=$(choose_ss_method)
    PASS=$(openssl rand -base64 32)

cat >"$CONFIG_FILE"<<EOF
{
  "inbounds":[{
    "port":$PORT,
    "protocol":"shadowsocks",
    "settings":{
      "method":"$METHOD",
      "password":"$PASS",
      "network":"tcp,udp"
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF

    echo "ss://$(echo -n "$METHOD:$PASS" | base64 -w0)@$(ip):$PORT#$REMARK"
}

# =========================================================
# Mode 3: Trojan Reality
# =========================================================
mode_trojan() {
    read -rp "备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    PASS=$(uuid)

    KEYS=$($XRAY_BIN x25519)
    PRI=$(echo "$KEYS" | awk '/PrivateKey/ {print $2}')
    PBK=$(echo "$KEYS" | awk '/PublicKey/ {print $2}')
    SID=$(openssl rand -hex 4)

cat >"$CONFIG_FILE"<<EOF
{
  "inbounds":[{
    "port":$PORT,
    "protocol":"trojan",
    "settings":{"clients":[{"password":"$PASS"}]},
    "streamSettings":{
      "network":"tcp",
      "security":"reality",
      "realitySettings":{
        "dest":"addons.mozilla.org:443",
        "serverNames":["addons.mozilla.org"],
        "privateKey":"$PRI",
        "shortIds":["$SID"],
        "fingerprint":"chrome",
        "xver":0
      }
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF

    echo "trojan://$PASS@$(ip):$PORT?security=reality&sni=addons.mozilla.org&pbk=$PBK&sid=$SID&fp=chrome#$REMARK"
}

# =========================================================
# Menu
# =========================================================
main_menu() {
while true; do
clear
echo "EXRAY v1.0"
echo "1) VLESS Reality Vision"
echo "2) Shadowsocks"
echo "3) Trojan Reality"
echo "0) Exit"
read -rp "选择: " c
case "$c" in
    1) mode_vless; service_restart ;;
    2) mode_ss; service_restart ;;
    3) mode_trojan; service_restart ;;
    0) exit 0 ;;
esac
read -rp "回车继续..."
done
}

# =========================================================
# Main
# =========================================================
check_root
check_sys
command -v xray >/dev/null || { deps; install_xray; service_start; }
main_menu
