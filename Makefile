# home-llm-gateway 常用命令
# 用法：make <target>；make help 查看全部命令
# 开发环境：macOS/Linux 均适用（GNU Make）

WEB_DIR      := web
LOGDIR       := .tmp/logs
AGENT_CONFIG := agent-config.yml
GATEWAY_BIN  := target/debug/gateway
AGENT_BIN    := target/debug/agent
MOCK_BIN     := target/debug/mock-llm

# k6 宏观压测参数（命令行注入，不写死机器特定值）：
#   make bench-k6 KEY=sk-xxx GATEWAY_URL=http://IP:9090 VUS=20 DUR=30s
#   make bench-admission KEY=sk-xxx GATEWAY_URL=http://IP:9090 VUS=200 DUR=20s MODEL=qwen2.5
KEY ?= sk-missing
GATEWAY_URL ?= http://127.0.0.1:8080
VUS ?= 20
DUR ?= 30s
MODEL ?= qwen2.5
LIMIT ?= 20

.PHONY: help setup certs certs-required web-install web-build web-dev build build-debug fmt clippy check test bench bench-k6 \
        bench-admission bench-admission-local release \
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

web-format: ## 检查前端格式（prettier，P3-21）
	cd $(WEB_DIR) && pnpm format:check

web-lint: ## 前端静态检查（oxlint，P3-21；warnings 也算失败）
	cd $(WEB_DIR) && pnpm lint

web-test: ## 前端单元/渲染测试（vitest，P3-21）
	cd $(WEB_DIR) && pnpm test

web-dev: ## 前端开发服务器（Vite :5173，代理到网关，需先起网关）
	cd $(WEB_DIR) && pnpm dev

## ---------- 构建与测试 ----------

build: ## 编译 release 二进制（target/release/）
	cargo build --release --bin gateway --bin agent --bin mock-llm

# `make dev` 跑的是 target/debug/ 下的三个二进制。以前它**只依赖生成的配置**，不依赖构建：
# 全新 clone、`cargo clean` 之后三条 nohup 全部 "No such file or directory"，但配方不检查存活，
# 最后照样打印"✔ 全栈已启动"——一个静默的空栈（P2-20）。cargo 自己会跳过已最新的 crate，
# 所以把它挂成 dev 的前置几乎不花时间。
build-debug: ## 编译 debug 二进制（target/debug/，`make dev` 的前置）
	cargo build --bin gateway --bin agent --bin mock-llm

fmt: ## 检查代码格式（cargo fmt --check）
	cargo fmt --check

clippy: ## clippy 检查（-D warnings，与 CI 同等门槛）
	cargo clippy --workspace --all-targets -- -D warnings

toolchain-check: ## 工具链三处一致（rust-toolchain.toml / Dockerfile / Cargo.toml 的 MSRV）
	./scripts/check-toolchain.sh

deny: ##（advisories/bans/licenses/sources 全跑，与 pre-commit hook / CI 同一条命令；首次/无网时需要 advisory 库）
	cargo deny check

check: fmt clippy deny nextest web-format web-lint web-test web-build toolchain-check ## 一键全量验证（= CI 的 Rust 门槛 + 前端格式/检查/测试/构建 + 工具链一致性：fmt / clippy / cargo deny / nextest / web-format / web-lint / web-test / web-build / toolchain-check）

test: ## 运行全部 Rust 测试（cargo 原生 runner，含 e2e；串行靠测试里的 #[serial]）
	cargo test

nextest: ## 同上，但用 nextest（CI 用的就是它；e2e 的串行由 .config/nextest.toml 的 test-group 保证）
	cargo nextest run --workspace

bench: ## 基准测试（Criterion）：make bench BENCH="-p proto -p gateway"
	cargo bench $(BENCH)

bench-k6: ## k6 宏观压测（SSE 长流）：make bench-k6 KEY=sk-xxx GATEWAY_URL=http://IP:9090
	k6 run -e GATEWAY_URL=$(GATEWAY_URL) -e GATEWAY_KEY=$(KEY) -e VUS=$(VUS) -e DURATION=$(DUR) \
		-e MODEL=$(MODEL) scripts/bench-k6/sse.js

# ---------------------------------------------------------------------------
# 出图接线（方案 1：把 k6 的 --summary-export 接到 report.py）——**故意注释掉**，
# 需要时去掉注释即可。默认不启用，原因：
#   1) 它只能自动化最后一步：一次 bench-k6 = 一轮跑批 = 图只能是"单轮模式"，
#      分离不出固定开销 F 与每事件开销 e（而这恰恰是 SSE 压测真正要回答的问题）。
#   2) 要分离 F/e 得手工跑两轮不同 CONTENT_LEN、再手工拼 manifest —— 摩擦在这里。
#   3) 往现有 bench-k6 里塞 --summary-export 会改变它的行为（多写一个文件）。
# 所以默认走 scripts/bench-k6/sweep.sh（方案 2）：两组扫描 + manifest + 出图 +
# 汇总表一次做完，下面留了对应的 target，取消注释即可用。
#
# CONTENT_LEN ?= 100
#
# bench-k6-export: ## 同上，但导出 summary JSON（单轮，供 report.py 用）
# 	k6 run --summary-export=.tmp/bench/k6-summary.json \
# 		-e GATEWAY_URL=$(GATEWAY_URL) -e GATEWAY_KEY=$(KEY) \
# 		-e VUS=$(VUS) -e DURATION=$(DUR) -e CONTENT_LEN=$(CONTENT_LEN) \
# 		scripts/bench-k6/sse.js
#
# bench-report: ## 用已有 export 出图：make bench-report RUNS=.tmp/bench/manifest-n.json
# 	python3 scripts/bench-k6/report.py --runs $(RUNS) -o sse-bench-report.svg \
# 		--where "$(GATEWAY_URL)" --vus "VUS=1" --dur "$(DUR)"
# 	rsvg-convert -o sse-bench-report.png sse-bench-report.svg
#
# LENS ?= 10 100
# VUSS ?= 1 5 20 40
# DUR_N ?= 30s
#
# bench-sweep: ## 两组扫描（N@VUS=1 与 VUS@固定流长）+ 出图 + 汇总表
# 	GATEWAY_URL=$(GATEWAY_URL) GATEWAY_KEY=$(KEY) LENS="$(LENS)" VUSS="$(VUSS)" \
# 		DUR=$(DUR) DUR_N=$(DUR_N) scripts/bench-k6/sweep.sh
# ---------------------------------------------------------------------------

bench-admission: ## 验证 HTTP 闸门（打外部 gateway /v1/slow）：make bench-admission KEY=sk-xxx GATEWAY_URL=http://IP:9090 VUS=200
	## 前置：被测 gateway 已配 max_concurrent_requests；agent 上游能响应 /v1/slow
	## （慢端点放大在途窗口）。429 占比突增点 = 闸门阈值；看 k6 报告 + 网关
	## /metrics 的 hlmg_active_requests 峰值是否贴住闸门值。
	k6 run -e GATEWAY_URL=$(GATEWAY_URL) -e GATEWAY_KEY=$(KEY) -e VUS=$(VUS) \
		-e DURATION=$(DUR) -e MODEL=$(MODEL) scripts/bench-k6/admission.js

bench-admission-local: ## 本地自建栈验证闸门：make bench-admission-local [LIMIT=20] [VUS=200]
	## 输出 hlmg_active_requests 峰值，应精确等于 LIMIT。
	bash scripts/bench-admission-local.sh $(LIMIT) $(VUS)

release: ## 多平台打包到 dist/（见 scripts/build-release.sh）
	bash scripts/build-release.sh

## ---------- 运行 ----------

run-gateway: gateway-config.yml ## debug 运行 cloud-gateway（需 web/dist 才有 UI，缺则提示页）
	cargo run -p gateway -- --config gateway-config.yml

run-mock: ## debug 运行 mock-llm（127.0.0.1:11435）
	cargo run -p mock-llm -- --addr 127.0.0.1:11435

run-agent: $(AGENT_CONFIG) ## debug 运行 edge-agent（连本地网关，转发到 mock-llm）
	cargo run -p agent -- --config $(AGENT_CONFIG)

dev: build-debug gateway-config.yml $(AGENT_CONFIG) ## 一键起全栈（mock-llm + gateway + agent，后台，日志在 .tmp/logs/；会先编译）
	@mkdir -p $(LOGDIR)
	@echo "== 启动 mock-llm (11435) =="
	@nohup $(MOCK_BIN) --addr 127.0.0.1:11435 --name mock-llm > $(LOGDIR)/mock-llm.log 2>&1 & echo $$! > .tmp/mock-llm.pid
	@sleep 0.5
	@echo "== 启动 gateway (8080 / UDP 4433) =="
	@nohup $(GATEWAY_BIN) --config gateway-config.yml > $(LOGDIR)/gateway.log 2>&1 & echo $$! > .tmp/gateway.pid
	@sleep 0.5
	@echo "== 启动 agent =="
	@nohup $(AGENT_BIN) --config $(AGENT_CONFIG) > $(LOGDIR)/agent.log 2>&1 & echo $$! > .tmp/agent.pid
	@sleep 1
	@# 存活检查（P2-20）：以前不管进程死没死都报"✔ 全栈已启动"，二进制缺失时就是一个静默空栈。
	@# 现在任一进程没活下来就失败退出，并把该进程日志末尾贴出来，好让人一眼看到原因。
	@for p in mock-llm gateway agent; do \
		pid=$$(cat .tmp/$$p.pid 2>/dev/null); \
		if [ -z "$$pid" ] || ! kill -0 "$$pid" 2>/dev/null; then \
			echo "✘ $$p 没能起来（pid=$${pid}），$(LOGDIR)/$$p.log 末尾："; \
			tail -n 20 $(LOGDIR)/$$p.log 2>/dev/null; \
			echo "已起来的进程用 make stop 收掉。"; \
			exit 1; \
		fi; \
	done
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

# 证书存在性检查：certs/out/ 是 gitignored 的，新 clone 的项目没有，
# 配置里引用的证书路径必须先生成（make certs / make setup）
# 注意：用 order-only 依赖（|）——只保证执行顺序、不触发目标重建，
#       否则每次 make 都会把用户手动改过的配置覆盖回默认值
certs-required:
	@if [ ! -f certs/out/ca.crt ] || [ ! -f certs/out/server.crt ] || [ ! -f certs/out/client.crt ]; then \
		echo "✖ 缺少开发证书（certs/out/），先执行: make certs"; \
		exit 1; \
	fi

gateway-config.yml: | certs-required
	@echo "生成本地开发 gateway-config.yml（admin_token: dev-admin）..."
	@printf 'listen_addr: "0.0.0.0:8080"\nquic_addr: "0.0.0.0:4433"\ncert: certs/out/server.crt\nkey: certs/out/server.key\nca: certs/out/ca.crt\nadmin_token: dev-admin\nkeys_file: keys.db\n' > gateway-config.yml

$(AGENT_CONFIG): | certs-required
	@echo "生成本地 agent 配置 $(AGENT_CONFIG)..."
	@printf 'cloud_addr: "127.0.0.1:4433"\nca: certs/out/ca.crt\ncert: certs/out/client.crt\nkey: certs/out/client.key\nagent_id: "edge-1"\nupstream: "http://127.0.0.1:11435"\nmax_concurrency: 4\n' > $(AGENT_CONFIG)
