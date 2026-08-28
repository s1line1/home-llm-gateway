# syntax=docker/dockerfile:1
# home-llm-gateway 多阶段构建镜像
#
# 构建：
#   docker build -t home-llm-gateway .
#   国内加速 crates 下载：docker build --build-arg USE_CN_MIRROR=1 -t home-llm-gateway .
#   Apple Silicon Mac 给 x86 服务器出镜像：docker build --platform linux/amd64 ...
#
# 运行网关（云服务器）：
#   docker run -d --name gateway --restart unless-stopped \
#     -v /etc/home-llm-gateway:/config -p 8443:8443 -p 4433:4433/udp \
#     home-llm-gateway gateway --config /config/gateway-config.yml
#
# 运行 agent（LLM 机器）：
#   docker run -d --name agent --restart always --network host \
#     -v /etc/home-llm-gateway:/config \
#     home-llm-gateway agent --config /config/agent-config.yml
#
# 镜像内含 gateway / agent / mock-llm 三个二进制。

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
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["--config", "/config/gateway-config.yml"]
