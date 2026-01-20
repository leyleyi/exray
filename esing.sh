#!/bin/bash
# =========================================================
# ESING - sing-box 一键管理脚本 - Powered by Leyi
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

SING_BIN="$(command -v sing-box || echo "/usr/local/bin/sing-box")"
CONFIG_FILE="/usr/local/etc/sing-box/config.json"
SCRIPT_PATH="/usr/local/bin/esing"

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
    curl -s --max-time 5 https://api.ipify.org || curl -s --max-time 5 ifconfig.me
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
            echo -e "${YELLOW}未识别的系统: $OS，尝试继续...${PLAIN}"
            ;;
    esac

    echo -e "${GREEN}依赖安装完成${PLAIN}"
}

# ---------------- 安装 sing-box ----------------
install_singbox() {
    mkdir -p /usr/local/etc/sing-box /usr/local/bin
    if [ -x "$SING_BIN" ]; then
        echo -e "${YELLOW}sing-box 已安装 ($(sing-box version 2>/dev/null || echo '未知版本'))${PLAIN}"
        return 0
    fi

    echo -e "${BLUE}正在下载最新 sing-box...${PLAIN}"
    read -rp "请输入Github代理(结尾带 / 可留空)： " GITHUB_PROXY
    GITHUB_PROXY=$(echo "$GITHUB_PROXY" | xargs)
    [[ -n "$GITHUB_PROXY" && ! "$GITHUB_PROXY" =~ /$ ]] && GITHUB_PROXY="${GITHUB_PROXY}/"

    VER=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
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
    echo -e "${BLUE}下载地址：${FULL_URL}${PLAIN}"
    if ! wget -qO "$TMP/sing-box.tar.gz" "$FULL_URL"; then
        echo -e "${YELLOW}代理下载失败，尝试直连...${PLAIN}"
        if ! wget -qO "$TMP/sing-box.tar.gz" "$DOWNLOAD_URL"; then
            echo -e "${RED}下载失败。请尝试：${PLAIN}"
            echo -e "2. 手动下载：https://github.com/SagerNet/sing-box/releases/download/$VER/sing-box-${VER_NO_V}-linux-${A}.tar.gz"
            echo -e "   上传后解压：tar -xzf 文件名.tar.gz && install -m755 sing-box /usr/local/bin/sing-box"
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
        echo -e "${RED}配置文件检查失败，无法重启${PLAIN}"
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
generate_common_inbound() {
    local type="$1" remark="$2" port="$3" extra="$4"
    cat > "$CONFIG_FILE" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "$type",
    "tag": "in",
    "listen": "::",
    "listen_port": $port,
    $extra
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
}

mode_vless_reality() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)
    KEYS=$($SING_BIN generate reality-keypair)
    PRI=$(echo "$KEYS" | grep PrivateKey | awk '{print $2}' | tr -d '"')
    PBK=$(echo "$KEYS" | grep PublicKey | awk '{print $2}' | tr -d '"')
    SHORTID=$(openssl rand -hex 4)

    generate_common_inbound "vless" "$REMARK" "$PORT" "
    \"users\": [{\"uuid\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true,
      \"reality\": {
        \"enabled\": true,
        \"handshake\": {\"server\": \"addons.mozilla.org\", \"server_port\": 443},
        \"private_key\": \"$PRI\",
        \"short_id\": [\"$SHORTID\"]
      }
    }"

    echo -e "${GREEN}VLESS Reality 配置完成${PLAIN}"
    echo "vless://$UUID@$(ip):$PORT?security=reality&pbk=$PBK&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SHORTID#$REMARK"
}

mode_shadowsocks() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}

    echo -e "${YELLOW}选择加密方式：${PLAIN}"
    echo "1) 2022-blake3-aes-128-gcm (默认)"
    echo "2) 2022-blake3-aes-256-gcm"
    echo "3) chacha20-ietf-poly1305"
    echo "4) aes-256-gcm"
    echo "5) aes-128-gcm"
    read -rp "选项 [1-5，回车=1]: " ch

    case $ch in
        2) METHOD="2022-blake3-aes-256-gcm" ;;
        3) METHOD="chacha20-ietf-poly1305" ;;
        4) METHOD="aes-256-gcm" ;;
        5) METHOD="aes-128-gcm" ;;
        *) METHOD="2022-blake3-aes-128-gcm" ;;
    esac

    if [[ $METHOD == 2022-blake3-* ]]; then
        PASS=$(random_base64_32)
        echo "密钥 (32字节 base64): $PASS"
    else
        PASS=$(openssl rand -base64 16 | tr -d '\n\r=+/')
        echo "密码: $PASS"
    fi

    generate_common_inbound "shadowsocks" "$REMARK" "$PORT" "
    \"method\": \"$METHOD\",
    \"password\": \"$PASS\""

    SS_B64=$(echo -n "$METHOD:$PASS" | base64 -w0)
    echo "ss://$SS_B64@$(ip):$PORT#$REMARK"
}

mode_trojan() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    PASS=$(uuid)
    read -rp "SNI (默认 www.microsoft.com): " SNI
    SNI=${SNI:-www.microsoft.com}

    generate_common_inbound "trojan" "$REMARK" "$PORT" "
    \"users\": [{\"password\": \"$PASS\"}],
    \"tls\": {
      \"enabled\": true,
      \"server_name\": \"$SNI\"
    }"

    echo "trojan://$PASS@$(ip):$PORT?security=tls&sni=$SNI#$REMARK"
}

mode_tuic() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)
    PASS=$(openssl rand -base64 12 | tr -d '\n\r=+/')

    generate_common_inbound "tuic" "$REMARK" "$PORT" "
    \"users\": [{\"uuid\": \"$UUID\", \"password\": \"$PASS\"}],
    \"congestion_control\": \"bbr\",
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"]
    }"

    echo "tuic://$UUID:$PASS@$(ip):$PORT?congestion_control=bbr&sni=addons.mozilla.org#$REMARK"
}

mode_hysteria2() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    PASS=$(openssl rand -base64 20 | tr -d '\n\r=+/')

    read -rp "是否启用 salamander 混淆？(y/n，回车=n): " obfs_choice
    if [[ "$obfs_choice" == "y" || "$obfs_choice" == "Y" ]]; then
        OBFS_PASS=$(openssl rand -base64 16 | tr -d '\n\r=+/')
        OBFS="\"obfs\": {\"type\": \"salamander\", \"password\": \"$OBFS_PASS\"},"
        echo "混淆密码: $OBFS_PASS"
    else
        OBFS=""
    fi

    generate_common_inbound "hysteria2" "$REMARK" "$PORT" "
    \"users\": [{\"password\": \"$PASS\"}],
    $OBFS
    \"tls\": {\"enabled\": true}"

    echo "hysteria2://$PASS@$(ip):$PORT/?sni=addons.mozilla.org#$REMARK"
}

mode_anytls() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}
    PASSWORD=$(openssl rand -base64 32 | tr -d '\n\r=+/')
    NAME="$(openssl rand -hex 4)"
    cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "level": "info"
  },
  "inbounds": [{
    "type": "anytls",
    "tag": "anytls-in",
    "listen": "::",
    "listen_port": $PORT,
    "users": [
      {
        "name": "$NAME",
        "password": "$PASSWORD"
      }
    ],
    "padding_scheme": []  // 使用默认 padding scheme（官方推荐留空或 []）
    // tls 可选添加 reality / uTLS 等伪装（当前保持简单）
  }],
  "outbounds": [{
    "type": "direct",
    "tag": "direct"
  }]
}
EOF

    echo -e "${GREEN}AnyTLS 配置已生成${PLAIN}"
    echo "anytls://${PASSWORD}@$(ip):${PORT}?name=${NAME}#${REMARK} (实验性协议)"
    echo -e "${YELLOW}正在检查配置文件语法...${PLAIN}"
    TEST_OUTPUT=$($SING_BIN check -c "$CONFIG_FILE" 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}配置文件语法检查通过${PLAIN}"
    else
        echo -e "${RED}配置文件语法检查失败，请检查配置${PLAIN}"
        echo -e "${YELLOW}错误信息：${PLAIN}"
        echo "$TEST_OUTPUT"
    fi
}

mode_socks() {
    read -rp "节点备注: " REMARK
    read -rp "端口(回车随机): " PORT
    PORT=${PORT:-$(port)}

    generate_common_inbound "socks" "$REMARK" "$PORT" "\"users\": []"

    echo "socks5://$(ip):$PORT#$REMARK"
}

mode_ss_to_vless() {
    read -rp "输入远程 VLESS reality 链接: " LINK
    # 简易解析（实际生产建议完善）
    UUID=$(echo "$LINK" | grep -oP '(?<=//)[^@]+')
    HOST_PORT=$(echo "$LINK" | grep -oP '(?<=@)[^?]+')
    ADDR=${HOST_PORT%%:*}
    PORT=${HOST_PORT##*:}
    PBK=$(echo "$LINK" | grep -oP '(?<=pbk=)[^&]+')
    SID=$(echo "$LINK" | grep -oP '(?<=sid=)[^#&]+')
    SNI=$(echo "$LINK" | grep -oP '(?<=sni=)[^&]+')

    read -rp "本地监听端口(回车随机): " LOCAL_PORT
    LOCAL_PORT=${LOCAL_PORT:-$(port)}
    read -rp "节点备注: " REMARK

    METHOD="2022-blake3-aes-128-gcm"
    PASS=$(random_base64_32)

    cat > "$CONFIG_FILE" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "shadowsocks",
    "tag": "ss-in",
    "listen": "::",
    "listen_port": $LOCAL_PORT,
    "method": "$METHOD",
    "password": "$PASS"
  }],
  "outbounds": [{
    "type": "vless",
    "tag": "remote",
    "server": "$ADDR",
    "server_port": $PORT,
    "uuid": "$UUID",
    "flow": "xtls-rprx-vision",
    "tls": {
      "enabled": true,
      "reality": {
        "enabled": true,
        "public_key": "$PBK",
        "short_id": ["$SID"]
      },
      "server_name": "$SNI"
    }
  }]
}
EOF

    SS_B64=$(echo -n "$METHOD:$PASS" | base64 -w0)
    echo "ss://$SS_B64@$(ip):$LOCAL_PORT#$REMARK"
}

mode_vless_to_ss() {
    read -rp "输入远程 Shadowsocks 链接: " SS_LINK
    # 简易解析
    SS_B64=$(echo "${SS_LINK#ss://}" | cut -d@ -f1)
    SS_DECODE=$(echo "$SS_B64" | base64 -d)
    METHOD_PASS=${SS_DECODE%@*}
    METHOD=${METHOD_PASS%%:*}
    PASS=${METHOD_PASS#*:}
    HOST_PORT=${SS_LINK#*@}
    HOST_PORT=${HOST_PORT%%#*}
    ADDR=${HOST_PORT%%:*}
    PORT=${HOST_PORT##*:}

    read -rp "本地端口(回车随机): " LOCAL_PORT
    LOCAL_PORT=${LOCAL_PORT:-$(port)}
    read -rp "节点备注: " REMARK

    UUID=$(uuid)
    KEYS=$($SING_BIN generate reality-keypair)
    PRI=$(echo "$KEYS" | grep PrivateKey | awk '{print $2}' | tr -d '"')
    PBK=$(echo "$KEYS" | grep PublicKey | awk '{print $2}' | tr -d '"')
    SHORTID=$(openssl rand -hex 4)

    cat > "$CONFIG_FILE" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "vless",
    "tag": "vless-in",
    "listen": "::",
    "listen_port": $LOCAL_PORT,
    "users": [{"uuid": "$UUID", "flow": "xtls-rprx-vision"}],
    "tls": {
      "enabled": true,
      "reality": {
        "enabled": true,
        "handshake": {"server": "addons.mozilla.org", "server_port": 443},
        "private_key": "$PRI",
        "short_id": ["$SHORTID"]
      }
    }
  }],
  "outbounds": [{
    "type": "shadowsocks",
    "tag": "remote-ss",
    "server": "$ADDR",
    "server_port": $PORT,
    "method": "$METHOD",
    "password": "$PASS"
  }]
}
EOF

    echo "vless://$UUID@$(ip):$LOCAL_PORT?security=reality&pbk=$PBK&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SHORTID#$REMARK"
}

enable_bbr() {
    cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system
    echo -e "${GREEN}BBR 已启用(需重启系统生效)${PLAIN}"
}

show_config_path() {
    echo -e "${GREEN}配置文件路径：${PLAIN}${YELLOW}$CONFIG_FILE${PLAIN}"
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
        echo " 6) AnyTLS (实验)"
        echo " 7) Socks5"
        echo " 8) SS → VLESS-reality 中继"
        echo " 9) VLESS-reality → SS 中继"
        echo "10) 显示配置文件路径"
        echo "11) 开启 BBR"
        echo "12) 重启 sing-box"
        echo "13) 停止 sing-box"
        echo "14) 卸载 sing-box"
        echo " 0) 退出"
        echo -e "${BLUE}====================================${PLAIN}"

        read -rp "请输入选项 [0-14]: " choice

        case "$choice" in
            1) mode_vless_reality; service_restart ;;
            2) mode_shadowsocks; service_restart ;;
            3) mode_trojan; service_restart ;;
            4) mode_tuic; service_restart ;;
            5) mode_hysteria2; service_restart ;;
            6) mode_anytls; service_restart ;;
            7) mode_socks; service_restart ;;
            8) mode_ss_to_vless; service_restart ;;
            9) mode_vless_to_ss; service_restart ;;
            10) show_config_path ;;
            11) enable_bbr ;;
            12) service_restart ;;
            13) stop_singbox ;;
            14) uninstall_singbox; exit 0 ;;
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