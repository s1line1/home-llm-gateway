#!/usr/bin/env bash
# 工具链三处一致性：`rust-toolchain.toml` 是**唯一来源**。
#
# 为什么要有这个检查（项目扫描"工具链三重漂移"）：本地、CI、Docker 曾经各用一套"当刻的
# stable"，于是 clippy 的新 lint 只在某一个版本上报——实测过"本地全绿 → CI 红"
# （`clippy::result_large_err`）。钉版本 + 机器化比对之后，升级工具链是一次显式、可 review
# 的改动，而不是某天 CI 自己变红。
#
# 比对四处：
#   1) `rust-toolchain.toml` 的 channel（必须是具体版本，不能是 stable/beta/nightly）；
#   2) **每一份**构建 Rust 的 Dockerfile 的 `FROM rust:<channel>-<suite>`；
#   3) **每一份**构建 Rust 的 Dockerfile 的 `ARG RUST_TOOLCHAIN=<channel>` 默认值；
#   4) `Cargo.toml` 的 `rust-version`（MSRV，只到 major.minor——"用什么编译"与"最低能编译什么"
#      是两个问题，所以只比前缀）。
#
# 为什么是"逐份"且**自动发现**：部署镜像是 `crates/gateway/Dockerfile`（gateway + Dashboard）。
# 把文件列表写死，将来新加一份（例如 `crates/agent/Dockerfile`）就不会被校验，变成没人看的
# 漂移点——而"工具链只有一个来源"正是这个脚本存在的理由。所以这里枚举仓库里所有 Dockerfile
# （优先 `git ls-files`，它顺带排除 `target/`、`node_modules/` 里的杂项；不在 git 仓库里就退回
# `find`），只对其中**真的在构建 Rust**的逐个比对。不构建 Rust 的镜像（例如将来某个纯前端
# 镜像）与工具链无关，自动跳过；一份都没发现则**报错**——"检查静默落空"比"漏掉一份"更危险。
#
# 用法：`./scripts/check-toolchain.sh`（CI 与 `make check` 都会跑）。改工具链时只改
# `rust-toolchain.toml` + 这里的另外几处，然后跑一遍它。
set -euo pipefail
cd "$(dirname "$0")/.."

channel="$(sed -n 's/^channel *= *"\([^"]*\)"/\1/p' rust-toolchain.toml)"
if [ -z "$channel" ]; then
    echo "rust-toolchain.toml: 没有 channel 字段" >&2
    exit 1
fi
case "$channel" in
    stable | beta | nightly)
        echo "rust-toolchain.toml: channel 是浮动的 '$channel'——请钉到具体版本（如 1.97.1）" >&2
        exit 1
        ;;
esac
case "$channel" in
    *.*.*) ;;
    *)
        echo "rust-toolchain.toml: channel '$channel' 看不出补丁号；请钉到 x.y.z" >&2
        exit 1
        ;;
esac
minor="${channel%.*}"
# 版本号里的 `.` 在 grep -E 里是通配符，先转义再拼进正则（否则 `1.97.1` 会匹配 `1x97y1`）。
channel_re="${channel//./\\.}"

# 仓库里所有 Dockerfile（相对仓库根、换行分隔）：`Dockerfile` 与 `*Dockerfile` 两种命名都认。
# 注意 git 的 pathspec：不带斜杠的 `Dockerfile` 只匹配**根级**那份，跨目录要靠 `*Dockerfile`。
list_dockerfiles() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files 'Dockerfile' '*Dockerfile'
    else
        find . -type f \( -name 'Dockerfile' -o -name '*Dockerfile' \) \
            -not -path './target/*' -not -path './web/node_modules/*' | sed 's|^\./||'
    fi
}

# "在构建 Rust"的判据：用了 rust 基底，或声明了工具链 ARG。
# `FROM` 后面允许 `--platform=...` 之类的旗标，所以不写死 `^FROM rust:`。
builds_rust() {
    grep -qE '^FROM( +--[^ ]+)* +rust:|^ARG RUST_TOOLCHAIN=' "$1"
}

checked=0
while IFS= read -r df; do
    [ -n "$df" ] || continue
    [ -f "$df" ] || continue
    builds_rust "$df" || continue
    if ! grep -qE "^FROM( +--[^ ]+)* +rust:${channel_re}-" "$df"; then
        echo "$df: 期望 'FROM rust:${channel}-<suite>'（与 rust-toolchain.toml 一致）" >&2
        exit 1
    fi
    if ! grep -qE "^ARG RUST_TOOLCHAIN=${channel_re}$" "$df"; then
        echo "$df: 期望 'ARG RUST_TOOLCHAIN=${channel}'（与 rust-toolchain.toml 一致）" >&2
        exit 1
    fi
    checked=$((checked + 1))
done < <(list_dockerfiles)

if [ "$checked" -eq 0 ]; then
    echo "没有发现任何构建 Rust 的 Dockerfile——这个检查已经落空，请核对发现逻辑（或确认本仓库还有镜像）。" >&2
    exit 1
fi

if ! grep -q "^rust-version = \"${minor}\"$" Cargo.toml; then
    echo "Cargo.toml: 期望 'rust-version = \"${minor}\"'（MSRV，只写 major.minor）" >&2
    exit 1
fi

echo "工具链三处一致：channel=${channel}（已比对 ${checked} 份构建 Rust 的 Dockerfile；Cargo rust-version=${minor}）"
