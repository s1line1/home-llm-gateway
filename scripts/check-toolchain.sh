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
#   2) `Dockerfile` 的 `FROM rust:<channel>-<suite>`；
#   3) `Dockerfile` 的 `ARG RUST_TOOLCHAIN=<channel>` 默认值；
#   4) `Cargo.toml` 的 `rust-version`（MSRV，只到 major.minor——"用什么编译"与"最低能编译什么"
#      是两个问题，所以只比前缀）。
#
# 用法：`./scripts/check-toolchain.sh`（CI 与 `make check` 都会跑）。改工具链时只改
# `rust-toolchain.toml` + 这里的另外三处，然后跑一遍它。
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

if ! grep -q "^FROM rust:${channel}-" Dockerfile; then
    echo "Dockerfile: 期望 'FROM rust:${channel}-<suite>'（与 rust-toolchain.toml 一致）" >&2
    exit 1
fi
if ! grep -q "^ARG RUST_TOOLCHAIN=${channel}$" Dockerfile; then
    echo "Dockerfile: 期望 'ARG RUST_TOOLCHAIN=${channel}'（与 rust-toolchain.toml 一致）" >&2
    exit 1
fi
if ! grep -q "^rust-version = \"${minor}\"$" Cargo.toml; then
    echo "Cargo.toml: 期望 'rust-version = \"${minor}\"'（MSRV，只写 major.minor）" >&2
    exit 1
fi

echo "工具链三处一致：channel=${channel}（Dockerfile 同版本，Cargo rust-version=${minor}）"
