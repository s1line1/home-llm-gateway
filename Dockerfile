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
# 镜像内含 gateway / agent / mock-llm 三个二进制**以及编好的 Dashboard**：
# 容器内既不用挂载宿主机的 `web/dist`，也**不用写 `ui_dir`** —— `config.rs::default_ui_dir()`
# 的默认值就是下面那个 COPY 目标 `/usr/local/share/home-llm-gateway/web`（见 DEPLOY.md §11.5）。
# 也可以直接用仓库根的 `docker-compose.yml`（网关 + 可选 agent）。

# 构建基底**必须与运行阶段的发行版对齐**：运行阶段是 `debian:bookworm-slim`（Debian 12，
# glibc 2.36），所以构建基底也用 `-bookworm` 变体。若换成 Debian 13（trixie，glibc 2.41）的基底，
# 链出来的 gateway / agent 在 bookworm 里根本起不来：
#   /usr/local/bin/gateway: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found
# 症状很隐蔽：**镜像能构建成功**，`mock-llm --version` 也正常（它依赖少），只有 gateway/agent
# 一启动就死。（另一条路是把运行阶段换成 `debian:trixie-slim`，但那样产物就要求 glibc ≥ 2.38。）
#
# 版本**必须与仓库 `rust-toolchain.toml` 的 channel 一致**（`scripts/check-toolchain.sh` 会校验）：
# 镜像里预装的就是这个版本的工具链，于是构建完全不碰网络。曾经这里钉 1.95、而仓库文件写
# `channel = "stable"`：rustup 找不到 "stable" 就去 static.rust-lang.org 下整套工具链
# （约 130 MB）——实测这一步在网络层面**挂住不返回**（日志停在 `downloading 5 components`：
# 7 分钟零字节、CPU 0.1%、磁盘零增长），这才是"镜像构建跑不完"的根本原因。
FROM rust:1.97.1-bookworm AS builder

# 工具链显式钉死：`RUSTUP_TOOLCHAIN` 优先级高于 rust-toolchain.toml，指到镜像里已有的那一套，
# 即使以后仓库文件的 channel 与镜像不同，构建也不会因为去下载工具链而挂住。
# 想临时试别的版本：--build-arg RUST_TOOLCHAIN=stable（那时需要能访问 rustup 源，
# 或另外配 RUSTUP_DIST_SERVER 国内镜像）。
ARG RUST_TOOLCHAIN=1.97.1
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

# ===== 前端（Dashboard）构建阶段 =====
#
# 目的：**把 Dashboard 编进镜像**，容器内不再依赖宿主机挂 `web/dist`（`TODO.md` 那条
# 「镜像不含 web/dist」于 2026-09-24 收口）。
# 单独成一个阶段是为了运行镜像里**不留 Node**：Node 只在 build 期存在，运行阶段只多一份静态产物。
#
# 版本跟着 CI 走，而不是跟着某台开发机走：`.github/workflows/ci.yml` 的前端 job 是
# **node 22 + pnpm 10**，而这个锁文件（`web/pnpm-lock.yaml`，lockfileVersion 9.0）就是在那套
# 组合下天天跑 `pnpm install --frozen-lockfile` 的。本机是 node 24 + pnpm 11，镜像若照抄就会
# 造出"只有镜像里才有的组合"——没人验过，坏了也说不清是谁的问题。`-bookworm-slim` 只是与运行
# 阶段同发行版族（产物是纯静态文件，不涉及 glibc）。两个 tag 的存在性都核过。
FROM node:22-bookworm-slim AS web-builder

# npm 镜像：与 crates / apt 同理（同一台 ECS 出网约 0.42 MB/s，直连 registry.npmjs.org 更慢）。
# 想回到官方源：--build-arg NPM_MIRROR=
ARG NPM_MIRROR=https://registry.npmmirror.com
RUN if [ -n "$NPM_MIRROR" ]; then npm config set registry "$NPM_MIRROR"; fi

# pnpm 用 **npm 装**而不是 corepack：corepack 取 pnpm 走的是它自己的 registry 设置
# （`COREPACK_NPM_REGISTRY`，默认官方源），**不跟随**上面的 `npm config` ⇒ 墙内那台机器上容易卡在
# 这一步。`npm install -g` 走的就是配好的镜像源，行为可预期；也省得赌以后的 Node 还带不带 corepack。
# 版本取 CI 的同一个主版本（`pnpm/action-setup@v4` 的 `version: 10`）：`--frozen-lockfile` 要求
# pnpm 能原样接受这份锁文件，跟随 CI 就等于跟着一个有持续验证的组合。
ARG PNPM_VERSION=10
RUN npm install -g "pnpm@$PNPM_VERSION"

WORKDIR /build/web
# ① 依赖层：只拷清单 ⇒ 改前端源码不会让 `pnpm install` 重跑
#    ⚠️ 反过来不成立：Rust 那层的 `COPY . .` 也包含 `web/`，所以**改一个前端文件会让 Rust 源码层
#    缓存失效**（release 重编）。这是既有行为（不是这次引入的），真要优化得把那一层的 COPY 收窄成
#    `crates/` + 几个清单文件——留给以后，别在同一次改动里动构建基座。
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# ② 构建层：`vite.config.ts` 读 `../Cargo.toml` 的 `[workspace.package].version` 注入
#    `__GATEWAY_VERSION__`（P3-20 的单一来源），所以工作区 Cargo.toml 必须落在 `/build/Cargo.toml`；
#    `pnpm build` 末尾还会跑 `scripts/check-bundle.mjs`（审计标记泄漏守卫）——它红了整次构建就失败，
#    这正是我们要的：镜像里的产物必须和本地构建走同一道门。
COPY Cargo.toml /build/Cargo.toml
COPY web/ ./
RUN pnpm build

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

# Dashboard 静态产物（`web-builder` 阶段构建）。**位置必须在挂载点之外**：容器里相对路径按
# **进程 CWD**（`/etc/home-llm-gateway`，见 DEPLOY.md §11.1）解析，而那个目录是配置 + 证书 +
# `keys.db` 的挂载点 —— 产物放进去会被宿主目录**遮住**，`/` 照样是"UI 未构建"。
# 所以放 `/usr/local/share/...`，并把 `config.rs::default_ui_dir()` 的默认值指向**同一个路径**：
# 于是容器**不写 `ui_dir` 也有 Dashboard**（有配置则用配置）。⚠️ 改这个路径要两处一起改
# （这里 + `default_ui_dir`），`config.rs` 里那条断言会盯着。
COPY --from=web-builder /build/web/dist /usr/local/share/home-llm-gateway/web

# 工作目录 = 配置目录：配置里的**相对路径**（`ui_dir`、`keys_file` 等）按进程 CWD 解析
# （`gateway/src/config.rs` 不按配置文件所在目录重写路径），所以必须显式定 CWD，
# 语义与 `deploy/gateway.service` 的 `WorkingDirectory=/etc/home-llm-gateway` 保持一致。
WORKDIR /etc/home-llm-gateway
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["--config", "/etc/home-llm-gateway/gateway-config.yml"]
