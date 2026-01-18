#!/bin/bash

# Function to detect the OS and install dependencies accordingly
install_dependencies() {
    if [ -f /etc/debian_version ]; then
        # Ubuntu/Debian
        apt update -y
        apt install -y curl unzip jq
    elif [ -f /etc/alpine-release ]; then
        # Alpine
        apk update
        apk add curl unzip jq
    elif [ -f /etc/centos-release ] || [ -f /etc/redhat-release ]; then
        # CentOS/RHEL
        yum update -y || dnf update -y
        yum install -y curl unzip jq || dnf install -y curl unzip jq
    else
        echo "Unsupported OS. Exiting."
        exit 1
    fi
}

# Function to install Xray
install_xray() {
    if ! command -v xray &> /dev/null; then
        echo "Installing Xray..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    else
        echo "Xray is already installed."
    fi
}

# Function to generate VLESS Reality config
generate_vless_reality() {
    read -p "Enter port: " port
    read -p "Enter SNI (e.g., www.example.com): " sni

    uuid=$(xray uuid)

    config='{
      "inbounds": [
        {
          "port": '"$port"',
          "protocol": "vless",
          "settings": {
            "clients": [
              {
                "id": "'"$uuid"'"
              }
            ],
            "decryption": "none"
          },
          "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
              "show": false,
              "dest": "'"$sni"':443",
              "xver": 0,
              "serverNames": ["'"$sni"'"],
              "privateKey": "YOUR_PRIVATE_KEY",  # Generate with xray x25519
              "publicKey": "YOUR_PUBLIC_KEY",
              "shortIds": [""]  # Optional
            }
          }
        }
      ],
      "outbounds": [
        {
          "protocol": "freedom"
        }
      ]
    }'

    echo "$config" > /usr/local/etc/xray/config.json
    echo "VLESS Reality config generated. UUID: $uuid"
    echo "Link: vless://$uuid@your-server-ip:$port?security=reality&sni=$sni&fp=chrome&type=tcp#VLESS-Reality"
}

# Function to generate Shadowsocks 2022 config
generate_shadowsocks_2022() {
    read -p "Enter port: " port

    password=$(openssl rand -base64 16)

    config='{
      "inbounds": [
        {
          "port": '"$port"',
          "protocol": "shadowsocks",
          "settings": {
            "method": "2022-blake3-aes-128-gcm",
            "password": "'"$password"'",
            "network": "tcp,udp"
          }
        }
      ],
      "outbounds": [
        {
          "protocol": "freedom"
        }
      ]
    }'

    echo "$config" > /usr/local/etc/xray/config.json
    echo "Shadowsocks 2022 config generated. Password: $password"
    echo "Link: ss://2022-blake3-aes-128-gcm:$password@your-server-ip:$port#SS-2022"
}

# Function to generate Shadowsocks relay with VLESS Reality outbound
generate_shadowsocks_relay() {
    read -p "Enter VLESS Reality config link (e.g., vless://uuid@ip:port?...): " vless_link

    # Parse VLESS link (simplified parsing, assume standard format)
    uuid=$(echo $vless_link | sed 's/vless:\/\///' | cut -d'@' -f1)
    address_port=$(echo $vless_link | sed 's/vless:\/\///' | cut -d'@' -f2 | cut -d'?' -f1)
    address=$(echo $address_port | cut -d':' -f1)
    port=$(echo $address_port | cut -d':' -f2)
    params=$(echo $vless_link | cut -d'?' -f2)
    sni=$(echo $params | grep -oP 'sni=\K[^&]*')

    read -p "Enter local Shadowsocks port: " local_port
    password=$(openssl rand -base64 16)

    config='{
      "inbounds": [
        {
          "port": '"$local_port"',
          "protocol": "shadowsocks",
          "settings": {
            "method": "aes-256-gcm",
            "password": "'"$password"'",
            "network": "tcp,udp"
          }
        }
      ],
      "outbounds": [
        {
          "protocol": "vless",
          "settings": {
            "vnext": [
              {
                "address": "'"$address"'",
                "port": '"$port"',
                "users": [
                  {
                    "id": "'"$uuid"'",
                    "encryption": "none"
                  }
                ]
              }
            ]
          },
          "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
              "show": false,
              "dest": "'"$sni"':443",
              "xver": 0,
              "serverNames": ["'"$sni"'"],
              "privateKey": "YOUR_PRIVATE_KEY",
              "publicKey": "YOUR_PUBLIC_KEY"
            }
          }
        }
      ]
    }'

    echo "$config" > /usr/local/etc/xray/config.json
    echo "Shadowsocks relay config generated. Password: $password"
    echo "Relay Link: ss://aes-256-gcm:$password@your-local-ip:$local_port#SS-Relay"
}

# Main script
install_dependencies
install_xray

echo "Select mode:"
echo "1. Vless Reality"
echo "2. Shadowsocks2022"
echo "3. Shadowsocks中转"
read -p "Enter number: " choice

case $choice in
    1)
        generate_vless_reality
        ;;
    2)
        generate_shadowsocks_2022
        ;;
    3)
        generate_shadowsocks_relay
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# Restart Xray
systemctl restart xray || /usr/local/bin/xray run -c /usr/local/etc/xray/config.json

echo "Xray configured and restarted."
