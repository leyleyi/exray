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

# ---------------- 依赖安装 ----------------
deps() {
    echo -e "${BLUE}正在安装系统依赖...${PLAIN}"

    case "$OS" in
        ubuntu|debian)
            apt update -y && apt install -y curl wget jq unzip openssl ca-certificates
            ;;
        alpine)
            apk update && apk add curl wget jq unzip openssl ca-certificates bash
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

# ---------------- 安装 Xray ----------------
install_xray() {
    mkdir -p /usr/local/etc/xray
    if [ -x "$XRAY_BIN" ]; then
        echo -e "${YELLOW}Xray 已安装${PLAIN}"
        return 0
    fi

    echo -e "${BLUE}正在下载最新 Xray...${PLAIN}"
    VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    [ -z "$VER" ] || [ "$VER" = "null" ] && { echo -e "${RED}获取版本失败${PLAIN}"; exit 1; }

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) A=64 ;;
        aarch64) A=arm64-v8a ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    TMP=$(mktemp -d)
    wget -qO "$TMP/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$VER/Xray-linux-$A.zip" || {
        echo -e "${RED}下载失败${PLAIN}"; rm -rf "$TMP"; exit 1;
    }

    unzip -q "$TMP/xray.zip" -d "$TMP" || { echo -e "${RED}解压失败${PLAIN}"; rm -rf "$TMP"; exit 1; }
    install -m755 "$TMP/xray" "$XRAY_BIN"
    rm -rf "$TMP"

    echo -e "${GREEN}Xray 安装完成${PLAIN}"
}

# ---------------- Server ----------------
service_start() {
    if [ "$OS" = "alpine" ]; then
        # Alpine OpenRC
        cat > /etc/init.d/xray <<'OPENRC'
#!/sbin/openrc-run
name="xray"
description="Xray Proxy Server"
command="/usr/local/bin/xray"
command_args="run -c /usr/local/etc/xray/config.json"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"
output_log="/var/log/xray.log"
error_log="/var/log/xray.err"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"

depend() { need net; after firewall; }
start_pre() { checkpath --directory --mode 0755 /var/log; }
OPENRC
        chmod +x /etc/init.d/xray
        rc-update add xray default 2>/dev/null
        rc-service xray start
    else
        # systemd
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
    fi
    echo -e "${GREEN}Xray 服务已启动${PLAIN}"
}

service_restart() {
    if [ "$OS" = "alpine" ]; then
        rc-service xray restart 2>/dev/null && echo -e "${GREEN}Xray 已重启${PLAIN}"
    else
        systemctl restart xray && echo -e "${GREEN}Xray 已重启${PLAIN}"
    fi
}

stop_xray() {
    if [ "$OS" = "alpine" ]; then
        rc-service xray stop 2>/dev/null && echo -e "${GREEN}Xray 已停止${PLAIN}"
    else
        systemctl stop xray && echo -e "${GREEN}Xray 已停止${PLAIN}"
    fi
}

uninstall_xray() {
    stop_xray
    if [ "$OS" = "alpine" ]; then
        rc-update del xray default 2>/dev/null
        rm -f /etc/init.d/xray
    else
        systemctl disable xray 2>/dev/null
        rm -f /etc/systemd/system/xray.service
        systemctl daemon-reload 2>/dev/null
    fi
    rm -f "$XRAY_BIN" /usr/local/bin/exray
    rm -rf /usr/local/etc/xray /usr/local/share/xray
    echo -e "${GREEN}Xray 已卸载${PLAIN}"
}

# ---------------- 配置生成函数 ----------------
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

# 选择 Shadowsocks 加密方式
choose_ss_method() {
    echo -e "${YELLOW}选择 Shadowsocks 加密方式（回车默认使用首选）：${PLAIN}"
    echo " 1) 2022-blake3-aes-128-gcm（首选，推荐）"
    echo " 2) chacha20-ietf-poly1305"
    echo " 3) aes-256-gcm"
    echo " 4) aes-128-gcm"
    read -rp "请输入选项 [1-4，回车=1]: " choice
    case "$choice" in
        2) echo "chacha20-ietf-poly1305" ;;
        3) echo "aes-256-gcm" ;;
        4) echo "aes-128-gcm" ;;
        *) echo "2022-blake3-aes-128-gcm" ;;  # 默认
    esac
}

# ---------------- Mode 1: VLESS Reality Vision ----------------
mode_vless() {
    read -rp "节点备注: " REMARK
    read -rp "请输入端口(回车随机10000-65535): " PORT
    PORT=${PORT:-$(port)}
    UUID=$(uuid)
    KEYS=$($XRAY_BIN x25519)
    PRI=$(echo "$KEYS" | grep -i '^PrivateKey' | awk -F ': ' '{print $2}')
    PBK=$(echo "$KEYS" | grep -i '^PublicKey'   | awk -F ': ' '{print $2}')
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

    echo -e "${GREEN}VLESS Reality 配置已生成${PLAIN}"
    echo "vless://$UUID@$(ip):$PORT?security=reality&encryption=none&pbk=$PBK&fp=chrome&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID#$REMARK"
}

# ---------------- Mode 2: Shadowsocks ----------------
mode_ss() {
    read -rp "节点备注: " REMARK
    read -rp "请输入端口(回车随机10000-65535): " PORT
    PORT=${PORT:-$(port)}
    METHOD=$(choose_ss_method)
    PASS=$(openssl rand -base64 16 | tr -d '\n\r')

    cat > "$CONFIG_FILE" <<EOF
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

    echo -e "${GREEN}Shadowsocks ($METHOD) 配置已生成${PLAIN}"
    echo "ss://$(echo -n "$METHOD:$PASS" | base64 -w0)@$(ip):$PORT#$REMARK"
}

# ---------------- Mode 3: Trojan Reality ----------------
mode_trojan() {
    read -rp "节点备注: " REMARK
    read -rp "请输入端口(回车随机10000-65535): " PORT
    PORT=${PORT:-$(port)}
    PASSWORD=$(uuid)
    KEYS=$($XRAY_BIN x25519)
    PRI=$(echo "$KEYS" | grep -i '^PrivateKey' | awk -F ': ' '{print $2}')
    PBK=$(echo "$KEYS" | grep -i '^PublicKey'   | awk -F ': ' '{print $2}')
    read -rp "请输入 Reality SNI(默认 addons.mozilla.org): " SNI
    SNI=${SNI:-addons.mozilla.org}
    SID=$(openssl rand -hex 4)

    cat > "$CONFIG_FILE" <<EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": {
      "clients": [{
        "password": "$PASSWORD",
        "email": "$REMARK"
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$PRI",
        "shortIds": ["$SID"]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom"
  }]
}
EOF

    echo -e "${GREEN}Trojan Reality 配置已生成${PLAIN}"
    echo "trojan://$PASSWORD@$(ip):$PORT?security=reality&sni=$SNI&pbk=$PBK&sid=$SID&type=tcp#$REMARK"
}

# ---------------- Mode 4: SS → VLESS Reality Relay ----------------
mode_ss_relay() {
    read -rp "输入上游 VLESS 链接: " LINK
    parse_vless "$LINK"
    read -rp "节点备注: " REMARK
    read -rp "请输入本地端口(回车随机10000-65535): " PORT
    PORT=${PORT:-$(port)}
    METHOD=$(choose_ss_method)
    PASS=$(openssl rand -base64 16 | tr -d '\n\r')

    cat > "$CONFIG_FILE" <<EOF
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

    echo -e "${GREEN}SS → VLESS 中继 ($METHOD) 配置已生成${PLAIN}"
    echo "ss://$(echo -n "$METHOD:$PASS" | base64 -w0)@$(ip):$PORT#$REMARK"
}

# ---------------- Other ----------------
enable_bbr() {
    cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system
    echo -e "${GREEN}BBR 已启用(需重启系统生效)${PLAIN}"
}

show_config_path() {
    echo -e "${GREEN}当前配置文件路径：${PLAIN}"
    echo -e "${YELLOW}${CONFIG_FILE}${PLAIN}"
    echo ""
}

# ---------------- Main Menu ----------------
main_menu() {
    while true; do
        clear
        echo -e "${BLUE}====================================${PLAIN}"
        echo -e "${BLUE}      EXRAY 管理面板 - Powered by Leyi${PLAIN}"
        echo -e "${BLUE}====================================${PLAIN}"
        echo " 1) VLESS Reality Vision"
        echo " 2) Shadowsocks"
        echo " 3) Trojan + Reality"
        echo " 4) SS → VLESS Reality 中继"
        echo " 5) 显示当前配置文件路径"
        echo " 6) 开启 BBR 加速"
        echo " 7) 重启 Xray 服务"
        echo " 8) 停止 Xray 服务"
        echo " 9) 卸载 Xray"
        echo " 0) 退出程序"
        echo -e "${BLUE}====================================${PLAIN}"

        read -rp "请输入选项 [0-9]: " choice

        case "$choice" in
            1) mode_vless; service_restart ;;
            2) mode_ss; service_restart ;;
            3) mode_trojan; service_restart ;;
            4) mode_ss_relay; service_restart ;;
            5) show_config_path ;;
            6) enable_bbr ;;
            7) service_restart ;;
            8) stop_xray ;;
            9) uninstall_xray; exit 0 ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选项，请重新输入${PLAIN}" ;;
        esac

        echo ""
        read -rp "按 Enter 键返回主菜单..." dummy
    done
}

# ================= Main =================
check_root
check_sys

command -v xray >/dev/null 2>&1 || {
    deps
    install_xray
    service_start
}

main_menu