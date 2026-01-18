#!/bin/bash
# =========================================================
# EXRAY - Powered by Leyi
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

XRAY_BIN="/usr/local/bin/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"
SCRIPT_PATH="/usr/local/bin/exray"

# ---------------- 基础 ----------------
check_root() { [ "$EUID" -ne 0 ] && echo "Run as root" && exit 1; }
check_sys() { . /etc/os-release || exit 1; OS=$ID; }

# ---------------- 工具 ----------------
ip() { curl -s https://api.ipify.org || curl -s ifconfig.me; }
port() { shuf -i10000-60000 -n1 2>/dev/null || echo $((RANDOM%50000+10000)); }
uuid() { cat /proc/sys/kernel/random/uuid; }

# ---------------- 依赖 ----------------
deps() {
    case "$OS" in
        ubuntu|debian)
            apt update -y
            apt install -y curl wget jq unzip openssl ca-certificates
            ;;
        alpine)
            apk add curl wget jq unzip openssl ca-certificates bash
            ;;
    esac
}

# ---------------- 安装 Xray ----------------
install_xray() {
    [ -x "$XRAY_BIN" ] && return
    VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) A=64 ;;
        aarch64) A=arm64-v8a ;;
        *) echo "Unsupported arch"; exit 1 ;;
    esac
    TMP=$(mktemp -d)
    wget -qO "$TMP/xray.zip" \
      "https://github.com/XTLS/Xray-core/releases/download/$VER/Xray-linux-$A.zip"
    unzip -q "$TMP/xray.zip" -d "$TMP"
    install -m755 "$TMP/xray" "$XRAY_BIN"
    mkdir -p /usr/local/etc/xray
    rm -rf "$TMP"
}

# ---------------- 安装 exray 命令 ----------------
install_exray_cmd() {
    if [ ! -f "$SCRIPT_PATH" ]; then
        cp "$0" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        echo -e "${GREEN}已安装 exray 系统命令${PLAIN}"
    fi
}

# ---------------- systemd ----------------
service_start() {
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
After=network.target
[Service]
ExecStart=$XRAY_BIN run -c $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray --now
}

# ---------------- VLESS 解析 ----------------
parse_vless() {
    l=${1#*://}; l=${l%\#*}
    V_UUID=${l%%@*}
    r=${l#*@}
    ap=${r%%\?*}
    V_ADDR=${ap%%:*}
    V_PORT=${ap##*:}
    IFS='&'
    for i in ${r#*\?}; do
        k=${i%%=*}; v=${i#*=}
        case "$k" in
            sni) V_SNI=$v ;;
            pbk) V_PBK=$v ;;
            sid) V_SID=$v ;;
            flow) V_FLOW=$v ;;
            fp) V_FP=$v ;;
        esac
    done
    unset IFS
    [ -z "$V_SNI" ] && V_SNI="addons.mozilla.org"
    [ -z "$V_FP" ] && V_FP="chrome"
    [ -z "$V_SID" ] && V_SID=$(openssl rand -hex 4)
}

# ---------------- MODE 1 ----------------
mode_vless() {
    PORT=$(port)
    UUID=$(uuid)
    KEYS=$($XRAY_BIN x25519)
    PRI=$(awk '/Private/{print $3}' <<<"$KEYS")
    PUB=$(awk '/Public/{print $3}' <<<"$KEYS")
    SID=$(openssl rand -hex 4)

cat > $CONFIG_FILE <<EOF
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
        "shortIds":["$SID"]
      }
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF

    echo "vless://$UUID@$(ip):$PORT?security=reality&encryption=none&pbk=$PUB&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID"
}

# ---------------- MODE 2 ----------------
mode_ss() {
    PORT=$(port)
    PASS=$(openssl rand -base64 16 2>/dev/null | tr -d '\n\r') || pass=$(head -c 16 /dev/urandom | base64 2>/dev/null | tr -d '\n\r')

cat > $CONFIG_FILE <<EOF
{
  "inbounds":[{
    "port":$PORT,
    "protocol":"shadowsocks",
    "settings":{
      "method":"2022-blake3-aes-128-gcm",
      "password":"$PASS",
      "network":"tcp,udp"
    }
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF

    echo "ss://$(echo -n 2022-blake3-aes-128-gcm:$PASS | base64 -w0)@$(ip):$PORT"
}

# ---------------- MODE 3 ----------------
mode_trojan() {
    PORT=$(port)
    PASSWORD=$(cat /proc/sys/kernel/random/uuid) || uuid=$(openssl rand -hex 16 | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4-\5\6-\7\8-\9\10-\11\12\13\14\15\16/')
    read -rp "请输入 SNI（默认 addons.mozilla.org）: " SNI
    SNI=${SNI:-addons.mozilla.org}

cat > "$CONFIG_FILE" <<EOF
{
  "inbounds": [
    {
      "port": $PORT,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$PASSWORD"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "$SNI"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

    echo
    echo "Trojan 链接："
    echo "trojan://$PASSWORD@$(ip):$PORT?sni=$SNI"
}


# ---------------- MODE 4 ----------------
mode_ss_relay() {
    read -rp "输入 vless:// 链接: " LINK
    parse_vless "$LINK"

    PORT=$(port)
    PASS=$(openssl rand -base64 16 2>/dev/null | tr -d '\n\r') || pass=$(head -c 16 /dev/urandom | base64 2>/dev/null | tr -d '\n\r')

cat > $CONFIG_FILE <<EOF
{
  "inbounds":[{
    "port":$PORT,
    "protocol":"shadowsocks",
    "settings":{
      "method":"2022-blake3-aes-128-gcm",
      "password":"$PASS",
      "network":"tcp,udp"
    }
  }],
  "outbounds":[{
    "protocol":"vless",
    "settings":{
      "vnext":[{
        "address":"$V_ADDR",
        "port":$V_PORT,
        "users":[{
          "id":"$V_UUID",
          "encryption":"none",
          "flow":"$V_FLOW"
        }]
      }]
    },
    "streamSettings":{
      "network":"tcp",
      "security":"reality",
      "realitySettings":{
        "serverName":"$V_SNI",
        "publicKey":"$V_PBK",
        "shortId":"$V_SID",
        "fingerprint":"$V_FP"
      }
    }
  }]
}
EOF

    echo "ss://$(echo -n 2022-blake3-aes-128-gcm:$PASS | base64 -w0)@$(ip):$PORT"
}

# ---------------- MODE 5 ----------------
mode_vless_relay() {
    read -rp "请输入目标 VLESS Reality Vision 链接: " LINK
    parse_vless "$LINK"

    PORT=$(port)
    UUID=$(uuid)
    KEYS=$($XRAY_BIN x25519)
    PRI=$(awk '/Private/{print $3}' <<<"$KEYS")
    PUB=$(awk '/Public/{print $3}' <<<"$KEYS")
    SID=$(openssl rand -hex 4)

cat > $CONFIG_FILE <<EOF
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
        "shortIds":["$SID"]
      }
    }
  }],
  "outbounds":[{
    "protocol":"vless",
    "settings":{
      "vnext":[{
        "address":"$V_ADDR",
        "port":$V_PORT,
        "users":[{
          "id":"$V_UUID",
          "flow":"$V_FLOW"
        }]
      }]
    },
    "streamSettings":{
      "network":"tcp",
      "security":"reality",
      "realitySettings":{
        "serverName":"$V_SNI",
        "publicKey":"$V_PBK",
        "shortId":"$V_SID",
        "fingerprint":"$V_FP"
      }
    }
  }]
}
EOF

    echo "vless://$UUID@$(ip):$PORT?security=reality&encryption=none&pbk=$PUB&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID"
}

# ---------------- MODE 6 ----------------
enable_bbr() {
cat > /etc/sysctl.conf <<'EOF'
fs.file-max = 6815744
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
sysctl -p && sysctl --system
}

# ---------------- MODE 7 ----------------
service_restart() {
    systemctl restart xray && echo -e "${GREEN}Xray 已重启${PLAIN}"
}

# ---------------- MODE 8 ----------------
uninstall_xray() {
    systemctl stop xray 2>/dev/null
    systemctl disable xray 2>/dev/null
    rm -f /etc/systemd/system/xray.service
    rm -f /usr/local/bin/exray
    rm -rf /usr/local/etc/xray
    rm -f "$XRAY_BIN"
    echo -e "${GREEN}Xray 已卸载${PLAIN}"
}

# ================= MENU =================
check_root
check_sys
deps
install_xray
install_exray_cmd

echo "1) VLESS Reality Vision"
echo "2) Shadowsocks"
echo "3) Trojan"
echo "4) Shadowsocks → VLESS Reality"
echo "5) VLESS Reality → VLESS Reality"
echo "6) 开启 BBR 加速"
echo "7) 重启 Xray"
echo "8) 卸载 Xray"
echo "0) 退出"
read -rp "> " M


case "$M" in
    1) mode_vless ; service_start ;;
    2) mode_ss ; service_start ;;
    3) mode_trojan ; service_start ;;
    4) mode_ss_relay ; service_start ;;
    5) mode_vless_relay ; service_start ;;
    6) enable_bbr ;;
    7) service_restart ;;
    8) uninstall_xray ;;
    0) exit 0 ;;
esac
