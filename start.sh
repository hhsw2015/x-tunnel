#!/bin/bash
set -e

# --- START: 插入的 DNS 設定程式碼 ---

echo "--- 正在強制設定 DNS 為 1.1.1.1/1.0.0.1 ---"

# 覆寫 /etc/resolv.conf，確保在執行 curl 下載前使用指定的 DNS

echo "nameserver 1.1.1.1" > /etc/resolv.conf

echo "nameserver 1.0.0.1" >> /etc/resolv.conf

# --- END: 插入的 DNS 設定程式碼 ---

curl -L -f --retry 3 \
  https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-amd64 \
  -o cloudflared && chmod +x cloudflared

curl -L -f --retry 3 \
  https://github.com/hhsw2015/x-tunnel/releases/download/v1.1/x-tunnel-linux-amd64 \
  -o x-tunnel

chmod +x x-tunnel

ls

# ======== 请在这里修改你的配置 ========
#CLOUDFLARE_URL="x-tunnel-img.playingapi.tech" # 你的 cloudflared 域名
CLOUDFLARE_TOKEN="${1:-eyJhIjoiODllMDYzZWYxOGQ3ZmVjZjhlY2E2NTBiYWFjNzZjYmYiLCJ0IjoiYjgyYzE4ZGEtNTllNS00N2Y2LTk0Y2MtNGMzNzQxNDI1ZGJhIiwicyI6Ik1XUTRObUZqTnprdE5UVmpNeTAwWVRObUxUazVNREF0WVRSbE5qWTFORGsxT0dZeiJ9}"
X_TUNNEL_TOKEN="7bd57098-82bd-4dfa-b32c-9943a52d354f" # x-tunnel 共享 token
#LOCAL_ADDR="127.0.0.1:8888"                             # x-tunnel 监听地址

echo "启动 x-tunnel 服务端（监听 8888）..."
./x-tunnel -l ws://127.0.0.1:8888 -token $X_TUNNEL_TOKEN >x-tunnel.log 2>&1 &

sleep 3

echo "启动 cloudflared ..."
./cloudflared tunnel run --no-tls-verify --token $CLOUDFLARE_TOKEN >cf.log 2>&1 &

echo "============================================"
echo "部署成功！你的专属 x-tunnel 节点已上线"
echo ""
echo "============================================"

tail -f x-tunnel.log cf.log
