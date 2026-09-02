#!/usr/bin/env bash
# 多平台 release 构建脚本。
# 用法: scripts/build-release.sh [版本号]
# 遍历常见目标平台，已安装的 rustup target 会依次构建并打包到 dist/。
# 跨平台编译注意：
#   - macOS → Linux 需要交叉链接器（如 brew install filosottile/musl-cross/musl-cross），
#     或用 musl 目标（x86_64-unknown-linux-musl / aarch64-unknown-linux-musl）得到静态二进制。
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')}"
DIST="dist"
mkdir -p "$DIST"

TARGETS=(
  "$(rustc -vV | sed -n 's/^host: //p')" # 当前主机（优先）
  x86_64-unknown-linux-gnu               # 阿里云 ECS x86
  aarch64-unknown-linux-gnu              # 阿里云 ECS ARM
  aarch64-apple-darwin                   # edge 节点 Mac（Apple Silicon）
)

for target in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    echo "==> skip ${target}（未安装，可执行 rustup target add ${target}）"
    continue
  fi
  echo "==> build ${target} (release)"
  cargo build --release --target "$target" --bin gateway --bin agent --bin mock-llm
  tarball="${DIST}/home-llm-gateway-${VERSION}-${target}.tar.gz"
  tar -C "target/${target}/release" -czf "$tarball" gateway agent mock-llm
  echo "    -> ${tarball}"
done

echo "完成，产物在 ${DIST}/"
