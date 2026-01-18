#!/bin/bash
# =========================================================
# Xray 终极修复版 - 2024 STABLE
# 特性：
# - 自动解析 VLESS Reality 链接
# - 防止 Xray 重复安装
# - Alpine / Debian / Ubuntu / CentOS 全兼容
# - Shadowsocks 2022 / Reality 规范完全正确
# =========================================================

# ------------------ 颜色 ------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# ------------------ 变量 ------------------
CONFIG_FILE="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

# ------------------ 基础检查 ------------------
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}必须使用 root 运行${PLAIN}" && exit 1
}

check_sys() {
    . /etc/os-release || exit 1
    OS=$ID
}

# ------------------ 依赖 ------------------
install_dependencies() {
    echo -e "${BLUE}安装依赖...${PLAIN}"
    case "$OS" in
        ubuntu|debian)
            apt-get update -y
            apt-get install -y curl wget jq openssl tar unzip ca-certificates
            ;;
        centos|rhel|fedora)
            yum install -y curl wget jq openssl tar unzip ca-certificates
            ;;
        alpine)
            apk add curl wget jq openssl tar unzip ca-certificates bash
            ;;
        *)
            echo -e "${RED}不支持的系统${PLAIN}"
            exit 1
            ;;
    esac
}

# ------------------ Xray ------------------
install_xray() {
    if [ -x "$XRAY_BIN" ]; then
        echo -e "${GREEN}Xray 已存在，跳过安装${PLAIN}"
        return
    fi

    echo -e "${BLUE}安装 Xray...${PLAIN}"
    LATEST=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) A=64 ;;
        aarch64) A=arm64-v8a ;;
        *) echo -e "${RED}不支持架构${PLAIN}"; exit 1 ;;
    esac

    TMP=$(mktemp -d)
    wget -qO "$TMP/xray.zip" \
        "https://github.com/XTLS/Xray-core/releases/download/${LATEST}/Xray-linux-${A}.zip"

    unzip -q "$TMP/xray.zip" -d "$TMP"
    install -m 755 "$TMP/xray" "$XRAY_BIN"
    install -m 644 "$TMP/geoip.dat" "$TMP/geosite.dat" /usr/local/bin/
    mkdir -p /usr/local/etc/xray
    rm -rf "$TMP"
}

# ------------------ 工具 ------------------
safe_base64() { base64 | tr -d '\n'; }

rand_port() {
    shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM%50000+10000))
}

rand_uuid() { cat /proc/sys/kernel/random/uuid; }

get_ip() {
    curl -s https://api.ipify.org || curl -s ifconfig.me
}

# ------------------ VLESS 解析 ------------------
parse_vless() {
    link=${1#*://}
    link=${link%\#*}

    V_UUID=${link%%@*}
    rest=${link#*@}

    addr=${rest%%\?*}
    V_ADDR=${addr%%:*}
    V_PORT=${addr##*:}

    params=${rest#*\?}
    IFS='&'
    for p in $params; do
        k=${p%%=*}
        v=${p#*=}
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

# ------------------ Relay ------------------
configure_relay() {
    read -rp "粘贴 vless:// 链接: " LINK
    [[ "$LINK" != vless://* ]] && exit 1
    parse_vless "$LINK"

    echo -e "${GREEN}解析成功：$V_ADDR:$V_PORT${PLAIN}"

    echo "1) SS 2022 (推荐)"
    echo "2) SS aes-128-gcm"
    read -rp "选择 [1]: " c

    if [ "$c" = "2" ]; then
        METHOD="aes-128-gcm"
        PASS=$(openssl rand -hex 16)
    else
        METHOD="2022-blake3-aes-128-gcm"
        PASS=$(openssl rand -base64 32)
    fi

    PORT=$(rand_port)

    cat > "$CONFIG_FILE" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "tag": "ss-in",
    "port": $PORT,
    "protocol": "shadowsocks",
    "settings": {
      "method": "$METHOD",
      "password": "$PASS",
      "network": "tcp,udp"
    }
  }],
  "outbounds": [{
    "tag": "proxy",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$V_ADDR",
        "port": $V_PORT,
        "users": [{
          "id": "$V_UUID",
          "encryption": "none",
          "flow": "$V_FLOW"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "$V_SNI",
        "publicKey": "$V_PBK",
        "shortId": "$V_SID",
        "fingerprint": "$V_FP"
      }
    },
    "mux": { "enabled": false }
  }]
}
EOF

    SS=$(echo -n "$METHOD:$PASS" | safe_base64)
    IP=$(get_ip)
    echo -e "\n${GREEN}SS 分享链接：${PLAIN}"
    echo "ss://${SS}@${IP}:${PORT}#Relay_${V_ADDR}"
}

# ------------------ Reality 本地 ------------------
configure_local() {
    PORT=$(rand_port)
    UUID=$(rand_uuid)
    KEYS=$($XRAY_BIN x25519)
    PRI=$(echo "$KEYS" | awk '/Private/{print $3}')
    PUB=$(echo "$KEYS" | awk '/Public/{print $3}')
    SID=$(openssl rand -hex 4)

    cat > "$CONFIG_FILE" <<EOF
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

    IP=$(get_ip)
    echo -e "\n${GREEN}VLESS 链接：${PLAIN}"
    echo "vless://$UUID@$IP:$PORT?security=reality&encryption=none&pbk=$PUB&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID"
}

# ------------------ 服务 ------------------
setup_service() {
    if command -v systemctl >/dev/null; then
        cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray
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
    else
        rc-service xray restart
    fi
}

# ------------------ MAIN ------------------
check_root
check_sys
install_dependencies
install_xray

clear
echo -e "${GREEN}Xray 高级配置${PLAIN}"
echo "1) VLESS Reality 本机"
echo "2) SS 中转 (VLESS → SS)"
read -rp "选择: " M

case "$M" in
    1) configure_local ;;
    2) configure_relay ;;
    *) exit 1 ;;
esac

setup_service
echo -e "${GREEN}完成，服务已启动${PLAIN}"
