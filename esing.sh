#!/bin/bash
# =========================================================
# ESING - sing-box 一键管理脚本 - Powered by Leyi
# Modified: Removed relay modes, Added VMess mode
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

SING_BIN="$(command -v sing-box || echo "/usr/local/bin/sing-box")"
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
SCRIPT_PATH="/usr/local/bin/esing"
CERT_DIR="/usr/local/etc/sing-box/certs"

# ---------------- Check ----------------
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}请使用 root 权限运行${PLAIN}" && exit 1
}

check_sys() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_LIKE="${ID_LIKE:-}"
    else
        echo -e "${RED}无法识别系统${PLAIN}"
        exit 1
    fi
}

# ---------------- Tools ----------------
ip() {
    curl -s --max-time 5 https://api.ipify.org   || curl -s --max-time 5 ifconfig.me
}

port() {
    shuf -i 10000-65535 -n1 2>/dev/null || echo $((RANDOM % 55536 + 10000))
}

uuid() {
    cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "00000000-0000-0000-0000-000000000000"
}

random_base64_32() {
    openssl rand -base64 32 | tr -d '\n\r=+/' | cut -c1-43
}

random_base64_16() {
    openssl rand -base64 16 | tr -d '\n='
}

# ---------------- 生成自签名证书 ----------------
generate_self_signed_cert() {
    local domain=$1
    mkdir -p "$CERT_DIR"

    if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
        echo -e "${BLUE}正在生成自签名证书...${PLAIN}"
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
            -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
            -subj "/CN=$domain" \
            -addext "subjectAltName=DNS:$domain,DNS:*.$domain" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}证书生成成功${PLAIN}"
        else
            echo -e "${RED}证书生成失败${PLAIN}"
            return 1
        fi
    fi
    return 0
}

# ---------------- 依赖安装 ----------------
deps() {
    echo -e "${BLUE}正在安装系统依赖...${PLAIN}"

    case "$OS" in
        ubuntu|debian)
            apt update -y && apt install -y curl wget jq unzip openssl ca-certificates
            ;;
        alpine)
            apk update && apk add curl wget jq unzip openssl ca-certificates bash coreutils
            ;;
        centos|rhel|fedora)
            yum install -y curl wget jq unzip openssl ca-certificates
            ;;
        *)
            echo -e "${YELLOW}未识别的系统: $OS,尝试继续...${PLAIN}"
            ;;
    esac

    echo -e "${GREEN}依赖安装完成${PLAIN}"
}

# ---------------- 安装 sing-box ----------------
install_singbox() {
    mkdir -p /usr/local/etc/sing-box /usr/local/bin "$CERT_DIR"
    if [ -x "$SING_BIN" ]; then
        echo -e "${YELLOW}sing-box 已安装 ($(sing-box version 2>/dev/null || echo '未知版本'))${PLAIN}"
        return 0
    fi

    echo -e "${BLUE}正在下载最新 sing-box...${PLAIN}"
    read -rp "请输入Github代理(结尾带 / 可留空): " GITHUB_PROXY
    GITHUB_PROXY=$(echo "$GITHUB_PROXY" | xargs)
    [[ -n "$GITHUB_PROXY" && ! "$GITHUB_PROXY" =~ /$ ]] && GITHUB_PROXY="${GITHUB_PROXY}/"

    VER=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest   | jq -r .tag_name)
    [ -z "$VER" ] || [ "$VER" = "null" ] && { echo -e "${RED}获取版本失败${PLAIN}"; exit 1; }

    VER_NO_V="${VER#v}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)   A="amd64" ;;
        aarch64)  A="arm64" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac
    TMP=$(mktemp -d)
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/$VER/sing-box-${VER_NO_V}-linux-${A}.tar.gz"
    FULL_URL="${GITHUB_PROXY}${DOWNLOAD_URL}"
    echo -e "${BLUE}下载地址:${FULL_URL}${PLAIN}"
    if ! wget -qO "$TMP/sing-box.tar.gz" "$FULL_URL"; then
        echo -e "${YELLOW}代理下载失败,尝试直连...${PLAIN}"
        if ! wget -qO "$TMP/sing-box.tar.gz" "$DOWNLOAD_URL"; then
            echo -e "${RED}下载失败。请尝试:${PLAIN}"
            echo -e "2. 手动下载:https://github.com/SagerNet/sing-box/releases/download/$VER/sing-box-${VER_NO_V}-linux-${A}.tar.gz"
            echo -e "   上传后解压:tar -xzf 文件名.tar.gz && install -m755 sing-box /usr/local/bin/sing-box"
            rm -rf "$TMP"
            exit 1
        fi
    fi

    tar -xzf "$TMP/sing-box.tar.gz" -C "$TMP" --strip-components=1 || { echo -e "${RED}解压失败${PLAIN}"; rm -rf "$TMP"; exit 1; }
    install -m755 "$TMP/sing-box" "$SING_BIN"
    rm -rf "$TMP"

    echo -e "${GREEN}sing-box 安装完成 (版本 ${VER})${PLAIN}"
}

# ---------------- 服务管理 ----------------
service_start() {
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<'OPENRC'
#!/sbin/openrc-run
name="sing-box"
description="sing-box Proxy Server"
command="/usr/local/bin/sing-box"
command_args="run -c /usr/local/etc/sing-box/config.json"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.err"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"

depend() { need net; after firewall; }
start_pre() { checkpath --directory --mode 0755 /var/log; }
OPENRC
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default 2>/dev/null
        rc-service sing-box start
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target
[Service]
ExecStart=$SING_BIN run -c $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable sing-box --now
    fi
    echo -e "${GREEN}sing-box 服务已启动${PLAIN}"
}

service_restart() {
    if $SING_BIN check -c "$CONFIG_FILE" >/dev/null 2>&1; then
        if [ "$OS" = "alpine" ]; then
            rc-service sing-box restart 2>/dev/null && echo -e "${GREEN}sing-box 已重启${PLAIN}"
        else
            systemctl restart sing-box && echo -e "${GREEN}sing-box 已重启${PLAIN}"
        fi
    else
        echo -e "${RED}配置文件检查失败,无法重启${PLAIN}"
        $SING_BIN check -c "$CONFIG_FILE"
    fi
}

stop_singbox() {
    if [ "$OS" = "alpine" ]; then
        rc-service sing-box stop 2>/dev/null && echo -e "${GREEN}sing-box 已停止${PLAIN}"
    else
        systemctl stop sing-box && echo -e "${GREEN}sing-box 已停止${PLAIN}"
    fi
}

uninstall_singbox() {
    stop_singbox
    if [ "$OS" = "alpine" ]; then
        rc-update del sing-box default 2>/dev/null
        rm -f /etc/init.d/sing-box
    else
        systemctl disable sing-box 2>/dev/null
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload 2>/dev/null
    fi
    rm -f "$SING_BIN" "$SCRIPT_PATH"
    rm -rf /usr/local/etc/sing-box /usr/local/share/sing-box
    rm -f /var/log/sing-box.*
    echo -e "${GREEN}sing-box 已卸载${PLAIN}"
}

# ---------------- 配置生成 ----------------
mode_vless_reality() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)

    KEYS=$($SING_BIN generate reality-keypair)
    PRI=$(echo "$KEYS" | awk '/PrivateKey/ {print $2}')
    PBK=$(echo "$KEYS" | awk '/PublicKey/ {print $2}')
    SHORTID=$(openssl rand -hex 4)
    SNI="addons.mozilla.org"

cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        { "uuid": "$UUID", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$SNI",
            "server_port": 443
          },
          "private_key": "$PRI",
          "short_id": ["$SHORTID"]
        }
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

echo "vless://$UUID@$(ip):$PORT?encryption=none&security=reality&flow=xtls-rprx-vision&pbk=$PBK&sid=$SHORTID&sni=$SNI#$REMARK"
}

mode_vmess() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)
    read -rp "Alter ID (默认: 0): " ALTER_ID
    ALTER_ID=${ALTER_ID:-0}

    echo -e "${YELLOW}是否启用 TLS? (y/N):${PLAIN}"
    read -rp "选择: " USE_TLS
    TLS_ENABLED=false
    SNI=""
    CERT_PATH=""
    KEY_PATH=""
    TLS_CONFIG=""

    if [[ "$USE_TLS" =~ ^[Yy]$ ]]; then
        TLS_ENABLED=true
        read -rp "SNI(默认:addons.mozilla.org):" SNI_INPUT
        SNI=${SNI_INPUT:-addons.mozilla.org}
        generate_self_signed_cert "$SNI"
        CERT_PATH="$CERT_DIR/cert.pem"
        KEY_PATH="$CERT_DIR/key.pem"
        TLS_CONFIG=",
        \"tls\": {
          \"enabled\": true,
          \"server_name\": \"$SNI\",
          \"certificate_path\": \"$CERT_PATH\",
          \"key_path\": \"$KEY_PATH\"
        }"
    fi

    if [ "$TLS_ENABLED" = true ]; then
        cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vmess",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        {
          "uuid": "$UUID",
          "alterId": $ALTER_ID
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "certificate_path": "$CERT_DIR/cert.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF
        VM_CONFIG="{\"v\":\"2\",\"ps\":\"$REMARK\",\"add\":\"$(ip)\",\"port\":\"$PORT\",\"id\":\"$UUID\",\"aid\":\"$ALTER_ID\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"tls\",\"sni\":\"$SNI\",\"alpn\":\"\",\"fp\":\"\",\"scv\":\"true\"}"
        echo "vmess://$(echo -n "$VM_CONFIG" | base64 -w0)"
    else
        cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vmess",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        {
          "uuid": "$UUID",
          "alterId": $ALTER_ID
        }
      ]
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF
        VM_CONFIG="{\"v\":\"2\",\"ps\":\"$REMARK\",\"add\":\"$(ip)\",\"port\":\"$PORT\",\"id\":\"$UUID\",\"aid\":\"$ALTER_ID\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\",\"sni\":\"\",\"alpn\":\"\",\"fp\":\"\",\"scv\":\"false\"}"
        echo "vmess://$(echo -n "$VM_CONFIG" | base64 -w0)"
    fi
}

mode_shadowsocks() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}

    echo -e "${YELLOW}选择加密方式:${PLAIN}"
    echo "1) 2022-blake3-aes-128-gcm (默认)"
    echo "2) 2022-blake3-aes-256-gcm"
    echo "3) chacha20-ietf-poly1305"
    echo "4) aes-256-gcm"
    echo "5) aes-128-gcm"
    read -rp "选项 [1-5,回车=1]: " ch

    case $ch in
        2) METHOD="2022-blake3-aes-256-gcm" ;;
        3) METHOD="chacha20-ietf-poly1305" ;;
        4) METHOD="aes-256-gcm" ;;
        5) METHOD="aes-128-gcm" ;;
        *) METHOD="2022-blake3-aes-128-gcm" ;;
    esac

    if [[ $METHOD == "2022-blake3-aes-128-gcm" ]]; then
        PASS=$(random_base64_16)
        echo "密钥 (16字节 base64): $PASS"
    elif [[ $METHOD == "2022-blake3-aes-256-gcm" ]]; then
        PASS=$(random_base64_32)
        echo "密钥 (32字节 base64): $PASS"
    else
        PASS=$(openssl rand -base64 16 | tr -d '\n\r=+/')
        echo "密码: $PASS"
    fi

    cat > "$CONFIG_FILE" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "shadowsocks",
    "tag": "in",
    "listen": "::",
    "listen_port": $PORT,
    "method": "$METHOD",
    "password": "$PASS"
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

    SS_B64=$(echo -n "$METHOD:$PASS" | base64 -w0)
    echo "ss://$SS_B64@$(ip):$PORT#$REMARK"
}

mode_trojan() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机):" PORT
    PORT=${PORT:-$(port)}
    PASS=$(uuid)
    read -rp "SNI(默认 www.microsoft.com):" SNI
    SNI=${SNI:-www.microsoft.com}

    generate_self_signed_cert "$SNI"

cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "trojan",
      "listen": "::",
      "listen_port": $PORT,
      "users": [{ "password": "$PASS" }],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "certificate_path": "$CERT_DIR/cert.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

echo "trojan://$PASS@$(ip):$PORT?security=tls&sni=$SNI&insecure=1#$REMARK"
}

mode_tuic() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机):" PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)
    PASS=$(openssl rand -hex 8)
    SNI="addons.mozilla.org"

    generate_self_signed_cert "$SNI"

cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "tuic",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        { "uuid": "$UUID", "password": "$PASS" }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "alpn": ["h3"],
        "certificate_path": "$CERT_DIR/cert.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

echo "tuic://$UUID:$PASS@$(ip):$PORT?sni=$SNI&congestion_control=bbr&alpn=h3&insecure=1#$REMARK"
}

mode_hysteria2() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机):" PORT
    PORT=${PORT:-$(port)}
    PASS=$(openssl rand -hex 8)
    SNI="addons.mozilla.org"

    generate_self_signed_cert "$SNI"

cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        { "password": "$PASS" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "alpn": ["h3"],
        "certificate_path": "$CERT_DIR/cert.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

echo "hysteria2://$PASS@$(ip):$PORT?sni=$SNI&insecure=1#$REMARK"
}


mode_anytls() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机):" PORT
    PORT=${PORT:-$(port)}
    USER="user-$(openssl rand -hex 4)"
    PASS=$(openssl rand -hex 16)
    SNI="addons.mozilla.org"

    generate_self_signed_cert "$SNI"

cat > "$CONFIG_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "anytls",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        { "name": "$USER", "password": "$PASS" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "certificate_path": "$CERT_DIR/cert.pem",
        "key_path": "$CERT_DIR/key.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

echo "anytls://$PASS@$(ip):$PORT?name=$USER&sni=$SNI&insecure=1#$REMARK"
}

mode_socks() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}

    echo -e "${YELLOW}是否启用密码认证? (y/N):${PLAIN}"
    read -rp "选择: " USE_AUTH

    if [[ "$USE_AUTH" =~ ^[Yy]$ ]]; then
        read -rp "用户名 (默认: user): " USERNAME
        USERNAME=${USERNAME:-user}
        read -rp "密码 (回车随机生成): " PASSWORD
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(openssl rand -hex 12)
            echo -e "${GREEN}生成的密码: $PASSWORD${PLAIN}"
        fi

        cat > "$CONFIG_FILE" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "socks",
    "tag": "in",
    "listen": "::",
    "listen_port": $PORT,
    "users": [
      {
        "username": "$USERNAME",
        "password": "$PASSWORD"
      }
    ]
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
        echo "socks5://$USERNAME:$PASSWORD@$(ip):$PORT#$REMARK"
    else
        cat > "$CONFIG_FILE" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "socks",
    "tag": "in",
    "listen": "::",
    "listen_port": $PORT,
    "users": []
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
        echo "socks5://$(ip):$PORT#$REMARK"
    fi
}

enable_bbr() {
    cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536
vm.overcommit_ratio = 100
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 4096
net.core.default_qdisc = fq
net.ipv4.tcp_rmem = 4096 131070 67108864
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_pacing_ca_ratio = 110
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_sack = 1
vm.vfs_cache_pressure = 30
kernel.sched_autogroup_enabled = 0
kernel.numa_balancing = 0
EOF
    sysctl --system
    echo -e "${GREEN}BBR 已启用(需重启系统生效)${PLAIN}"
}

show_config_path() {
    echo -e "${GREEN}配置文件路径:${PLAIN}${YELLOW}$CONFIG_FILE${PLAIN}"
}

# ---------------- 主菜单 ----------------
main_menu() {
    while true; do
        clear
        echo -e "${BLUE}====================================${PLAIN}"
        echo -e "${BLUE}     ESING - sing-box 管理面板     ${PLAIN}"
        echo -e "${BLUE}====================================${PLAIN}"
        echo " 1) VLESS + Reality"
        echo " 2) Shadowsocks"
        echo " 3) Trojan (普通TLS)"
        echo " 4) TUIC v5"
        echo " 5) Hysteria2"
        echo " 6) AnyTLS"
        echo " 7) Socks5"
        echo " 8) VMess"
        echo " 9) 显示配置文件路径"
        echo "10) 开启 BBR"
        echo "11) 重启 sing-box"
        echo "12) 停止 sing-box"
        echo "13) 卸载 sing-box"
        echo " 0) 退出"
        echo -e "${BLUE}====================================${PLAIN}"

        read -rp "请输入选项 [0-13]: " choice

        case "$choice" in
            1) mode_vless_reality; service_restart ;;
            2) mode_shadowsocks; service_restart ;;
            3) mode_trojan; service_restart ;;
            4) mode_tuic; service_restart ;;
            5) mode_hysteria2; service_restart ;;
            6) mode_anytls; service_restart ;;
            7) mode_socks; service_restart ;;
            8) mode_vmess; service_restart ;;
            9) show_config_path ;;
            10) enable_bbr ;;
            11) service_restart ;;
            12) stop_singbox ;;
            13) uninstall_singbox; exit 0 ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选项${PLAIN}" ;;
        esac

        echo ""
        read -rp "按 Enter 返回主菜单..." dummy
    done
}

# ================= Main =================
check_root
check_sys

command -v sing-box >/dev/null 2>&1 || {
    deps
    install_singbox
    service_start
}

main_menu