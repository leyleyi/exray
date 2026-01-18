#!/usr/bin/env bash
# =====================================================================
# 一键 Xray 安装脚本 - SS → VLESS Reality 中转链路（每个节点只开一个端口）
# 模式1: 落地机（只暴露 VLESS + Reality 端口，如 443）
# 模式2: 中转机（只暴露 SS 端口，如 8443，出站到下游 VLESS Reality）
# Shadowsocks 使用 2022-blake3-aes-128-gcm（无需 TLS 证书）
# 支持 Ubuntu/Debian/Alpine/CentOS/Rocky/Alma 等
# ======================================================================

set -euo pipefail

RED='\033[1;31m' GREEN='\033[1;32m' YELLOW='\033[1;33m' BLUE='\033[1;34m'
PURPLE='\033[1;35m' CYAN='\033[1;36m' NC='\033[0m'

info()    { echo -e "\( {GREEN}[INFO] \){NC} $*"; }
warn()    { echo -e "\( {YELLOW}[WARN] \){NC} $*"; }
error()   { echo -e "\( {RED}[ERROR] \){NC} $*" >&2; exit 1; }
success() { echo -e "\( {GREEN}[OK] \){NC} $*"; }

XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
XRAY_LOG="/var/log/xray"
SERVICE_FILE="/etc/systemd/system/xray.service"

SS_METHOD="2022-blake3-aes-128-gcm"
SS_PORT=8443
SS_PSK=""
VLESS_PORT=443
VLESS_SNI="www.microsoft.com"
VLESS_UUID=""
VLESS_PBK=""
VLESS_PRIVK=""
DOWN_IP=""
DOWN_PORT=""
DOWN_UUID=""
DOWN_PBK=""
DOWN_SNI=""

get_ip() {
    curl -s4 icanhazip.com 2>/dev/null || curl -s4 ifconfig.me || echo "你的服务器IP"
}

install_deps() {
    if command -v apt >/dev/null; then
        apt update -qq && apt install -y -qq curl unzip jq openssl ca-certificates
    elif command -v apk >/dev/null; then
        apk add --no-cache curl unzip jq openssl ca-certificates
    elif command -v dnf >/dev/null; then
        dnf install -y -q curl unzip jq openssl ca-certificates
    else
        warn "请手动安装 curl unzip jq openssl"
    fi
}

download_xray() {
    LATEST=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r .tag_name)
    [[ -z "$LATEST" || "$LATEST" = "null" ]] && error "获取 Xray 版本失败"
    ARCH=$(uname -m | sed 's/x86_64/64/;s/aarch64/arm64-v8a/;s/armv[78].*/arm32-v7a/')
    URL="https://github.com/XTLS/Xray-core/releases/download/$LATEST/Xray-linux-$ARCH.zip"
    curl -L -o /tmp/xray.zip "$URL" && unzip -o /tmp/xray.zip xray geoip.dat geosite.dat -d /usr/local/bin/
    chmod 755 "$XRAY_BIN"
    rm -f /tmp/xray.zip
}

gen_vless_keys() {
    VLESS_UUID=$($XRAY_BIN uuid)
    keypair=$($XRAY_BIN x25519)
    VLESS_PRIVK=$(echo "$keypair" | grep Private | awk '{print $3}')
    VLESS_PBK=$(echo "$keypair" | grep Public | awk '{print $3}')
}

gen_ss_psk() {
    SS_PSK=$(openssl rand -base64 16 | tr -d '=')
}

ask_mode() {
    echo -e "\n请选择本机角色："
    echo "1) 落地机（只暴露 VLESS + Reality 端口，如 443）"
    echo "2) 中转机（只暴露 SS 端口，如 8443，出站到下游 VLESS Reality）"
    read -rp "输入 1 或 2: " MODE
    MODE=${MODE:-1}
}

ask_common() {
    if [[ $MODE == "1" ]]; then
        read -rp "VLESS Reality 端口 (默认 443): " tmp
        VLESS_PORT=${tmp:-443}
        read -rp "Reality SNI/伪装域名 (默认 www.microsoft.com): " tmp
        VLESS_SNI=${tmp:-"www.microsoft.com"}
    else
        read -rp "SS 监听端口 (默认 8443): " tmp
        SS_PORT=${tmp:-8443}
        read -rp "SS PSK (留空自动生成): " input
        if [[ -z "$input" ]]; then
            gen_ss_psk
            info "自动生成 PSK: $SS_PSK"
        else
            SS_PSK="$input"
        fi
    fi
}

ask_downstream_vless() {
    read -rp "下游落地机 IP 或域名: " DOWN_IP
    [[ -z "$DOWN_IP" ]] && error "不能为空"
    read -rp "下游 VLESS 端口 (默认 443): " tmp
    DOWN_PORT=${tmp:-443}
    read -rp "下游 UUID: " DOWN_UUID
    [[ -z "$DOWN_UUID" ]] && error "UUID 不能为空"
    read -rp "下游 Public Key (pbk): " DOWN_PBK
    [[ -z "$DOWN_PBK" ]] && error "Public Key 不能为空"
    read -rp "下游 SNI (默认 www.microsoft.com): " tmp
    DOWN_SNI=${tmp:-"www.microsoft.com"}
}

create_landing_config() {
    cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {"loglevel": "warning", "access": "$XRAY_LOG/access.log", "error": "$XRAY_LOG/error.log"},
  "inbounds": [{
    "port": $VLESS_PORT,
    "protocol": "vless",
    "settings": {"clients": [{"id": "$VLESS_UUID", "flow": "xtls-rprx-vision"}], "decryption": "none"},
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "$VLESS_SNI:443",
        "serverNames": ["$VLESS_SNI"],
        "privateKey": "$VLESS_PRIVK",
        "publicKey": "$VLESS_PBK",
        "shortIds": [""]
      }
    },
    "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
  }],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "block"}],
  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]}
}
EOF
}

create_relay_config() {
    cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {"loglevel": "warning", "access": "$XRAY_LOG/access.log", "error": "$XRAY_LOG/error.log"},
  "inbounds": [{
    "port": $SS_PORT,
    "protocol": "shadowsocks",
    "settings": {"method": "$SS_METHOD", "password": "$SS_PSK", "network": "tcp,udp"},
    "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
  }],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "$DOWN_IP",
          "port": $DOWN_PORT,
          "users": [{"id": "$DOWN_UUID", "flow": "xtls-rprx-vision", "encryption": "none"}]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$DOWN_SNI",
          "fingerprint": "chrome",
          "publicKey": "$DOWN_PBK",
          "shortId": ""
        }
      },
      "tag": "to-downstream"
    },
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["ss-inbound"], "outboundTag": "to-downstream"},
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}
    ]
  }
}
EOF
}

setup_service() {
    mkdir -p "$XRAY_DIR" "$XRAY_LOG"
    chmod 600 "$XRAY_DIR/config.json"

    if [[ -d /etc/systemd/system ]]; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=$XRAY_BIN run -c $XRAY_DIR/config.json
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now xray
    else
        warn "非 systemd，请手动启动: $XRAY_BIN run -c $XRAY_DIR/config.json"
    fi
}

show_result() {
    local ip=$(get_ip)
    if [[ $MODE == "1" ]]; then
        success "落地机 配置完成（只开端口 $VLESS_PORT）"
        echo -e "IP: ${GREEN}\( ip \){NC}"
        echo -e "端口: ${GREEN}\( VLESS_PORT \){NC}"
        echo -e "UUID: ${GREEN}\( VLESS_UUID \){NC}"
        echo -e "Public Key: ${GREEN}\( VLESS_PBK \){NC}"
        echo -e "SNI: ${GREEN}\( VLESS_SNI \){NC}"
        echo
        echo "分享链接示例（客户端直连用）："
        echo "vless://$VLESS_UUID@$ip:$VLESS_PORT?security=reality&encryption=none&pbk=$VLESS_PBK&type=tcp&flow=xtls-rprx-vision&sni=$VLESS_SNI#Reality"
    else
        success "中转机 配置完成（只开端口 $SS_PORT）"
        echo -e "本机 SS 端口: ${GREEN}\( SS_PORT \){NC}"
        echo -e "PSK: ${GREEN}\( SS_PSK \){NC}"
        echo -e "下游落地: ${GREEN}$DOWN_IP:\( DOWN_PORT \){NC}"
        echo
        echo "客户端 SS 连接信息："
        echo "服务器: $ip"
        echo "端口: $SS_PORT"
        echo "加密: $SS_METHOD"
        echo "密码: $SS_PSK"
    fi
}

main() {
    [[ $EUID -ne 0 ]] && error "请用 root 执行"

    install_deps
    download_xray
    ask_mode
    ask_common

    if [[ $MODE == "1" ]]; then
        gen_vless_keys
        create_landing_config
    else
        ask_downstream_vless
        create_relay_config
    fi

    setup_service
    show_result

    success "完成！查看日志：tail -f $XRAY_LOG/error.log"
    echo "更新 Xray：bash <(curl -Ls https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)"
}

main "$@"