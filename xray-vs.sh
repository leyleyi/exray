#!/bin/bash
# =========================================================
# Xray Ultimate Script - FINAL
# Modes:
# 1. VLESS Reality (xtls-rprx-vision)
# 2. Shadowsocks Direct
# 3. Shadowsocks Relay -> VLESS Reality (parse vless://)
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

XRAY_BIN="/usr/local/bin/xray"
CONFIG_FILE="/usr/local/etc/xray/config.json"

# ---------------- 基础 ----------------
check_root(){ [ "$EUID" -ne 0 ] && exit 1; }
check_sys(){ . /etc/os-release || exit 1; OS=$ID; }

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

install_xray() {
    [ -x "$XRAY_BIN" ] && return
    VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) A=64 ;;
        aarch64) A=arm64-v8a ;;
        *) exit 1 ;;
    esac
    TMP=$(mktemp -d)
    wget -qO "$TMP/xray.zip" \
      "https://github.com/XTLS/Xray-core/releases/download/$VER/Xray-linux-$A.zip"
    unzip -q "$TMP/xray.zip" -d "$TMP"
    install -m755 "$TMP/xray" "$XRAY_BIN"
    mkdir -p /usr/local/etc/xray
    rm -rf "$TMP"
}

ip(){ curl -s https://api.ipify.org || curl -s ifconfig.me; }
port(){ shuf -i10000-60000 -n1 2>/dev/null || echo $((RANDOM%50000+10000)); }
uuid(){ cat /proc/sys/kernel/random/uuid; }

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

# =========================================================
# MODE 1 : VLESS Reality xtls-rprx-vision
# =========================================================
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

    echo -e "${GREEN}VLESS 链接：${PLAIN}"
    echo "vless://$UUID@$(ip):$PORT?security=reality&encryption=none&pbk=$PUB&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID"
}

# =========================================================
# MODE 2 : Shadowsocks Direct
# =========================================================
mode_ss() {
    PORT=$(port)
    PASS=$(openssl rand -base64 32)

    cat > $CONFIG_FILE <<EOF
{
  "inbounds":[{
    "tag":"ss-in",
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

    SS=$(echo -n "2022-blake3-aes-128-gcm:$PASS" | base64 -w0)
    echo "ss://$SS@$(ip):$PORT"
}

# =========================================================
# MODE 3 : SS Relay -> VLESS Reality
# =========================================================
mode_relay() {
    read -rp "输入 vless:// 链接: " LINK
    parse_vless "$LINK"

    PORT=$(port)
    PASS=$(openssl rand -base64 32)

    cat > $CONFIG_FILE <<EOF
{
  "inbounds":[{
    "tag":"ss-in",
    "port":$PORT,
    "protocol":"shadowsocks",
    "settings":{
      "method":"2022-blake3-aes-128-gcm",
      "password":"$PASS",
      "network":"tcp,udp"
    }
  }],
  "outbounds":[{
    "tag":"proxy",
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
    },
    "mux":{"enabled":false}
  }]
}
EOF

    SS=$(echo -n "2022-blake3-aes-128-gcm:$PASS" | base64 -w0)
    echo -e "${GREEN}SS Relay 链接：${PLAIN}"
    echo "ss://$SS@$(ip):$PORT"
}

# ---------------- 服务 ----------------
service() {
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

# ================= MAIN =================
check_root
check_sys
deps
install_xray

echo -e "${GREEN}选择模式:${PLAIN}"
echo "1) VLESS Reality xtls"
echo "2) Shadowsocks"
echo "3) SS Relay → VLESS Reality"
read -rp "> " M

case "$M" in
    1) mode_vless ;;
    2) mode_ss ;;
    3) mode_relay ;;
    *) exit 1 ;;
esac

service
echo -e "${GREEN}完成${PLAIN}"
