#!/usr/bin/env bash
# 生成开发用证书（CA + 服务端 + 客户端），输出到 certs/out/。
# 生产环境请使用独立的 CA 管理流程，并为每个 agent 单独签发证书。
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out

# 1. CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout out/ca.key -out out/ca.crt -days 3650 \
  -subj "/CN=HomeLLM Dev CA"

# 2. 服务端证书（网关），SAN 覆盖 localhost / 127.0.0.1
openssl req -newkey rsa:2048 -nodes \
  -keyout out/server.key -out out/server.csr \
  -subj "/CN=gateway.local"
cat > out/server.ext <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in out/server.csr \
  -CA out/ca.crt -CAkey out/ca.key -CAcreateserial \
  -out out/server.crt -days 365 -extfile out/server.ext

# 3. 客户端证书（agent，mTLS）
openssl req -newkey rsa:2048 -nodes \
  -keyout out/client.key -out out/client.csr \
  -subj "/CN=home-agent-1"
cat > out/client.ext <<'EOF'
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in out/client.csr \
  -CA out/ca.crt -CAkey out/ca.key -CAcreateserial \
  -out out/client.crt -days 365 -extfile out/client.ext

rm -f out/*.csr out/*.ext
echo "certificates written to certs/out/"
echo "  ca.crt       - 分发到两端作为信任根"
echo "  server.crt/key - 网关使用"
echo "  client.crt/key - agent 使用"
