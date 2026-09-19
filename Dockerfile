# syntax=docker/dockerfile:1
# home-llm-gateway 多阶段构建镜像
#
# 构建：
#   docker build -t home-llm-gateway .
#   Apple Silicon Mac 给 x86 服务器出镜像：docker build --platform linux/amd64 ...
#
# 墙内构建**不要**关掉下面的镜像源：实测同一台阿里云 ECS 上，crates 包体走阿里云
# 1.17 MB/s、直连 static.crates.io 只有 21 KB/s（本项目要下 338 个 crate ≈ 74 MB）。
# 想回到官方源：--build-arg CRATES_MIRROR= --build-arg APT_MIRROR=
#
# 运行网关（云服务器）：
#   ⚠️ ENTRYPOINT 已经是 gateway 二进制，命令行里**不要再写一个 "gateway"**——那会被 clap
#      当成未声明的位置参数，容器以退出码 2 立刻退出（配 restart 就是崩溃重启循环）。
#   ⚠️ 挂载点必须与配置里的路径对齐：`gateway_config.example.yml` 用的是绝对路径
#      `/etc/home-llm-gateway/...`，所以这里做**同路径挂载**，配置可原样使用。
#      若改用 `-v /etc/home-llm-gateway:/config`，则 YAML 里的 cert/key/ca/keys_file
#      都要一起改成 `/config/...`，否则容器内找不到文件（见 DEPLOY.md §11）。
#   docker run -d --name gateway --restart unless-stopped \
#     -v /etc/home-llm-gateway:/etc/home-llm-gateway \
#     -p 8443:8443 -p 4433:4433/udp \
#     home-llm-gateway --config /etc/home-llm-gateway/gateway-config.yml
#
# 运行 agent（LLM 机器）：镜像里虽然也有 agent / mock-llm，但 ENTRYPOINT 固定是 gateway，
# 所以**必须用 --entrypoint 切换**，否则跑起来的还是网关：
#   docker run -d --name agent --restart always --network host \
#     --entrypoint /usr/local/bin/agent \
#     -v /etc/home-llm-gateway:/etc/home-llm-gateway \
#     home-llm-gateway --config /etc/home-llm-gateway/agent-config.yml
#
# 镜像内含 gateway / agent / mock-llm 三个二进制。
# 也可以直接用仓库根的 `docker-compose.yml`（网关 + 可选 agent）。

FROM rust:1.95 AS builder

# 工具链：**必须显式指定**，否则构建会挂死在这里。
# 仓库的 `rust-toolchain.toml` 写的是 `channel = "stable"`，而本镜像里装的是
# `1.95.0-x86_64-unknown-linux-gnu`。rustup 找不到 "stable" 就去 static.rust-lang.org 下整套
# 工具链（rustc/rust-std/cargo/clippy/rustfmt，约 130 MB）——实测这一步在网络层面**挂住不返回**
# （日志停在 `downloading 5 components`：7 分钟零字节、CPU 0.1%、磁盘零增长）。这才是"镜像构建
# 跑不完"的根本原因，跟 2 核编译快慢无关。
# `RUSTUP_TOOLCHAIN` 优先级高于 rust-toolchain.toml，指到镜像里已有的工具链后构建不碰网络。
# 想改用当前 stable（与 CI 一致）：--build-arg RUST_TOOLCHAIN=stable
# —— 那时需要能访问 rustup 源，或另外配 RUSTUP_DIST_SERVER 国内镜像。
ARG RUST_TOOLCHAIN=1.95.0
ENV RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN

# crates 镜像源。**关键是这个镜像要自己提供包体**：
# 索引（sparse index）决定“有哪些 crate”，包体地址写在索引 config.json 的 `dl` 字段里，
# 而 `replace-with` 是整源替换 —— 所以 `dl` 指向哪，包体就从哪下。
# 反例：tuna 的 index 里 `dl` 仍是 static.crates.io，只能加速索引、包体照样走原站（我们踩过）。
# 实测（同一台 ECS，serde 82KB）：
#   阿里云 1.17 MB/s · USTC 333 KB/s · rsproxy 195 KB/s · crates.io 直连 21 KB/s
ARG CRATES_MIRROR=sparse+https://mirrors.aliyun.com/crates.io-index/
RUN if [ -n "$CRATES_MIRROR" ]; then \
      mkdir -p /usr/local/cargo && \
      printf '[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\nregistry = "%s"\n' \
        "$CRATES_MIRROR" > /usr/local/cargo/config.toml; \
    fi

WORKDIR /build

# ① 清单层：只拷 Cargo.toml/Cargo.lock 并造最小骨架，**这一层只负责下载依赖**。
#    这样改源码不会让它失效——依赖不必重下（原来 74 MB 每次重下，是构建最慢的一段）。
#    骨架必须覆盖所有“自动发现”的 target：每个 bin 的 src/main.rs、proto 的 src/lib.rs，
#    以及两个 [[bench]]（proto/benches/frame.rs、gateway/benches/keystore.rs，无显式 path）。
COPY Cargo.toml Cargo.lock ./
COPY crates/proto/Cargo.toml crates/proto/
COPY crates/gateway/Cargo.toml crates/gateway/
COPY crates/agent/Cargo.toml crates/agent/
COPY crates/mock-llm/Cargo.toml crates/mock-llm/
RUN set -eux; \
    mkdir -p crates/proto/src crates/proto/benches \
             crates/gateway/src crates/gateway/benches \
             crates/agent/src crates/mock-llm/src; \
    : > crates/proto/src/lib.rs; \
    : > crates/proto/benches/frame.rs; \
    : > crates/gateway/benches/keystore.rs; \
    for b in gateway agent mock-llm; do printf 'fn main() {}\n' > "crates/$b/src/main.rs"; done; \
    cargo fetch --locked

# ② 源码层：依赖已在上一层缓存，这里只编译
COPY . .
RUN cargo build --release --bin gateway --bin agent --bin mock-llm

FROM debian:bookworm-slim

# apt 保留（要装 ca-certificates），但必须修掉两个坑，否则这一步会卡死：
#   ① `deb.debian.org` 在这个容器里解析到 IPv6（2a04:4e42:7b::644），而宿主机**没有全局
#      IPv6** → 连接被黑洞而不是快速失败。实测 `apt-get update` 超过 3 分钟不返回。
#      加 `Acquire::ForceIPv4` 即可（注意：apt 自己不会主动回退到 IPv4）。
#   ② 直连取一个 Release 文件 3.4s，同区镜像 0.09s。
ARG APT_MIRROR=mirrors.aliyun.com
RUN printf 'Acquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/99force-ipv4 \
    && if [ -n "$APT_MIRROR" ]; then \
         sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; \
       fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /build/target/release/agent /usr/local/bin/agent
COPY --from=builder /build/target/release/mock-llm /usr/local/bin/mock-llm
# 工作目录 = 配置目录：配置里的**相对路径**（`ui_dir`、`keys_file` 等）按进程 CWD 解析
# （`gateway/src/config.rs` 不按配置文件所在目录重写路径），所以必须显式定 CWD，
# 语义与 `deploy/gateway.service` 的 `WorkingDirectory=/etc/home-llm-gateway` 保持一致。
WORKDIR /etc/home-llm-gateway
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["--config", "/etc/home-llm-gateway/gateway-config.yml"]
