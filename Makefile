# home-llm-gateway 常用命令
# 用法：make <target>；make help 查看全部命令
# 开发环境：macOS/Linux 均适用（GNU Make）

WEB_DIR      := web
LOGDIR       := .tmp/logs
AGENT_CONFIG := agent-config.yml
GATEWAY_BIN  := target/debug/gateway
AGENT_BIN    := target/debug/agent
MOCK_BIN     := target/debug/mock-llm

# k6 宏观压测参数（make bench-k6 KEY=sk-xxx VUS=20 DUR=30s）
KEY ?= sk-missing
VUS ?= 20
DUR ?= 30s

.PHONY: help setup certs web-install web-build web-dev build test bench bench-k6 release \
        run-gateway run-agent run-mock dev dev-ui logs stop clean

help: ## 显示所有命令
	@grep -E '^[-a-zA-Z0-9_]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

## ---------- 一次性准备 ----------

setup: certs web-install ## 生成开发证书 + 安装前端依赖
	@echo "✔ 完成：certs/out 已生成，前端依赖已安装"

certs: ## 生成开发证书（certs/out/）
	bash certs/gen-dev.sh

web-install: ## 安装前端依赖（web/node_modules）
	cd $(WEB_DIR) && pnpm install

## ---------- 前端 ----------

web-build: ## 构建前端产物（web/dist，网关 / 即托管 Dashboard）
	cd $(WEB_DIR) && pnpm build

web-dev: ## 前端开发服务器（Vite :5173，代理到网关，需先起网关）
	cd $(WEB_DIR) && pnpm dev

## ---------- 构建与测试 ----------

build: ## 编译 release 二进制（target/release/）
	cargo build --release --bin gateway --bin agent --bin mock-llm

test: ## 运行全部 Rust 测试（含 e2e）
	cargo test

bench: ## 基准测试（Criterion）：make bench BENCH="-p proto -p gateway"
	cargo bench $(BENCH)

bench-k6: ## k6 宏观压测（SSE 长流）：make bench-k6 KEY=sk-xxx VUS=20 DUR=30s
	k6 run -e GATEWAY_URL=$${GATEWAY_URL:-http://127.0.0.1:8080} -e GATEWAY_KEY=$(KEY) -e VUS=$(VUS) -e DURATION=$(DUR) scripts/bench-k6/sse.js

release: ## 多平台打包到 dist/（见 scripts/build-release.sh）
	bash scripts/build-release.sh

## ---------- 运行 ----------

run-gateway: gateway-config.yml ## debug 运行 cloud-gateway（需 web/dist 才有 UI，缺则提示页）
	cargo run -p gateway -- --config gateway-config.yml

run-mock: ## debug 运行 mock-llm（127.0.0.1:11435）
	cargo run -p mock-llm -- --addr 127.0.0.1:11435

run-agent: $(AGENT_CONFIG) ## debug 运行 edge-agent（连本地网关，转发到 mock-llm）
	cargo run -p agent -- --config $(AGENT_CONFIG)

dev: gateway-config.yml $(AGENT_CONFIG) ## 一键起全栈（mock-llm + gateway + agent，后台，日志在 .tmp/logs/）
	@mkdir -p $(LOGDIR)
	@if [ ! -f certs/out/ca.crt ]; then echo "✖ 缺少证书，先执行 make certs"; exit 1; fi
	@echo "== 启动 mock-llm (11435) =="
	@nohup $(MOCK_BIN) --addr 127.0.0.1:11435 --name mock-llm > $(LOGDIR)/mock-llm.log 2>&1 & echo $$! > .tmp/mock-llm.pid
	@sleep 0.5
	@echo "== 启动 gateway (8080 / UDP 4433) =="
	@nohup $(GATEWAY_BIN) --config gateway-config.yml > $(LOGDIR)/gateway.log 2>&1 & echo $$! > .tmp/gateway.pid
	@sleep 0.5
	@echo "== 启动 agent =="
	@nohup $(AGENT_BIN) --config $(AGENT_CONFIG) > $(LOGDIR)/agent.log 2>&1 & echo $$! > .tmp/agent.pid
	@sleep 1
	@echo "✔ 全栈已启动："
	@echo "   管理面板 http://localhost:8080/   (admin_token: dev-admin)"
	@echo "   API      http://localhost:8080/v1/chat/completions"
	@echo "   日志     $(LOGDIR)/*.log （make logs 查看）"

dev-ui: web-build dev ## 构建前端并一键起全栈（含 Dashboard）

logs: ## 查看 dev 后台进程日志
	@tail -f $(LOGDIR)/gateway.log $(LOGDIR)/agent.log $(LOGDIR)/mock-llm.log

stop: ## 停止 dev 启动的全部后台进程
	@for p in gateway agent mock-llm; do \
		if [ -f .tmp/$$p.pid ]; then \
			kill $$(cat .tmp/$$p.pid) 2>/dev/null && echo "✔ 已停止 $$p" || echo "  $$p 未在运行"; \
			rm -f .tmp/$$p.pid; \
		fi; \
	done

## ---------- 清理 ----------

clean: ## 清理构建产物（Rust + 前端）
	cargo clean
	rm -rf $(WEB_DIR)/dist

## ---------- 配置文件生成（本地开发默认值） ----------

gateway-config.yml:
	@echo "生成本地开发 gateway-config.yml（admin_token: dev-admin）..."
	@printf 'listen_addr: "0.0.0.0:8080"\nquic_addr: "0.0.0.0:4433"\ncert: certs/out/server.crt\nkey: certs/out/server.key\nca: certs/out/ca.crt\nadmin_token: dev-admin\nkeys_file: keys.db\n' > gateway-config.yml

$(AGENT_CONFIG):
	@echo "生成本地 agent 配置 $(AGENT_CONFIG)..."
	@printf 'cloud_addr: "127.0.0.1:4433"\nca: certs/out/ca.crt\ncert: certs/out/client.crt\nkey: certs/out/client.key\nagent_id: "home-1"\nupstream: "http://127.0.0.1:11435"\nmax_concurrency: 4\n' > $(AGENT_CONFIG)
