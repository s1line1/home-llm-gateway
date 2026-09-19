# syntax=docker/dockerfile:1
# home-llm-gateway 多阶段构建镜像
#
# 构建：
#   docker build -t home-llm-gateway .
#   国内加速 crates 下载：docker build --build-arg USE_CN_MIRROR=1 -t home-llm-gateway .
#   Apple Silicon Mac 给 x86 服务器出镜像：docker build --platform linux/amd64 ...
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
ARG USE_CN_MIRROR=0
RUN if [ "$USE_CN_MIRROR" = "1" ]; then \
      mkdir -p /usr/local/cargo && \
      printf '[source.crates-io]\nreplace-with = "tuna"\n[source.tuna]\nregistry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"\n' \
        > /usr/local/cargo/config.toml; \
    fi
WORKDIR /build
COPY . .
RUN cargo build --release --bin gateway --bin agent --bin mock-llm

FROM debian:bookworm-slim
RUN apt-get update \
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
