#!/usr/bin/env bash
# 多平台 release 构建脚本（Linux 侧产出**静态** musl 二进制）。
#
# 用法：
#   scripts/build-release.sh [版本号] [--strict] [--target TRIPLE]... [--no-verify]
#
#   --strict      缺失的目标（未装 rustup target / 未装交叉工具链）也算失败；
#                 CI 一个 job 一个 target 时用它：装了却编不出来必须让流水线红。
#   --target T    只构建指定 triple，可重复；默认四个（见下）。
#   --no-verify   跳过静态性断言（只在本地"能不能编过"的快速试探时用）。
#
# 默认目标（顺序即产物顺序）：
#   host                           当前主机（优先）
#   x86_64-unknown-linux-musl      阿里云 ECS x86 / 任意 glibc 发行版
#   aarch64-unknown-linux-musl     阿里云 ECS ARM / Apple Silicon 上的 Linux 容器
#   aarch64-apple-darwin           edge 节点 Mac（Apple Silicon）
#
# 三个承重设计，别"顺手简化"：
#
# 1) Linux 侧**只出 musl 静态产物**，不再出 `*-unknown-linux-gnu`。
#    静态 ELF 不绑定 glibc 版本，一份产物落在任意发行版上都能跑。这正是
#    `crates/gateway/Dockerfile` 里那条血泪注释（构建基底与运行阶段 glibc 不一致 ⇒
#    镜像构建成功、启动那一刻 `GLIBC_2.38 not found`）要避免的一类问题：把 glibc
#    从交付面拿掉，就没有"基底必须对齐"这条隐性契约。
#
# 2) **静态性由脚本自己断言**（`file` 写 statically / static-pie linked；ELF 里不许有
#    PT_INTERP / NEEDED）。"提供静态二进制"不能只靠文件名里的 `musl`——`rustup
#    target add` 装了目标、但链接器仍是宿主机 cc 时，产物照样是动态的。
#
# 3) **未安装的目标默认跳过**（跨平台开发机常常只装得上其中几个），但装了之后
#    构建失败 / 断言失败一律算失败：脚本逐个跑完再汇总，不能裸跑 `cargo build`
#    让 `set -e` 在第一个失败目标处结束（排在后面的 aarch64-apple-darwin 才是
#    edge 机器真正要用的产物）。**一个都没建成 = 失败**（`dist/` 是空的，S2-11）。
#
# 交叉工具链（musl 目标）：
#   · Linux runner/主机：`apt-get install -y musl-tools`（提供 musl-gcc）
#   · macOS：brew install filosottile/musl-cross/musl-cross，或从 musl.cc 下
#     `<arch>-linux-musl-cross.tgz` 解包后用 MUSL_CROSS_DIR=/path/to/<arch>-linux-musl-cross
#     指过来（脚本会把它加进 PATH）
#   链接器名在不同环境里不一样（Linux 上是 `musl-gcc`，musl.cc 工具链是
#   `x86_64-linux-musl-gcc`），所以**不写进 `.cargo/config.toml`**，而是这里按 target
#   探测后注入 `CC_<target>` / `CARGO_TARGET_<TARGET>_LINKER`：钉死一个名字必然在
#   另一个环境里断掉。
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=""
STRICT=0
VERIFY=1
TARGETS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --strict) STRICT=1 ;;
    --no-verify) VERIFY=0 ;;
    --target)
      shift
      TARGETS+=("${1:?--target 需要一个 triple}")
      ;;
    --target=*) TARGETS+=("${1#*=}") ;;
    -h | --help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "未知参数：$1（--help 看用法）" >&2
      exit 2
      ;;
    *) VERSION="$1" ;;
  esac
  shift
done

VERSION="${VERSION:-$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')}"

if [ "${#TARGETS[@]}" -eq 0 ]; then
  TARGETS=(
    "$(rustc -vV | sed -n 's/^host: //p')" # 当前主机（优先）
    x86_64-unknown-linux-musl              # 阿里云 ECS x86
    aarch64-unknown-linux-musl             # 阿里云 ECS ARM
    aarch64-apple-darwin                   # edge 节点 Mac（Apple Silicon）
  )
fi

# 去重（保序）：在 Apple Silicon 上 `host` 就是 aarch64-apple-darwin，与上面最后一个显式目标
# 重复——不去重会把同一个包构建、打包两次，`dist/SHA256SUMS` 里也会出现两行同样的校验和
# （2026-09-28 实测踩到）。显式 `--target a --target a` 同理。
deduped=()
for t in "${TARGETS[@]}"; do
  already=0
  for seen in "${deduped[@]-}"; do
    if [ "$seen" = "$t" ]; then
      already=1
      break
    fi
  done
  if [ "$already" -eq 1 ]; then
    continue
  fi
  deduped+=("$t")
done
TARGETS=("${deduped[@]}")

DIST="dist"
mkdir -p "$DIST"

if [ -n "${MUSL_CROSS_DIR:-}" ]; then
  export PATH="${MUSL_CROSS_DIR}/bin:${PATH}"
fi

host_arch() {
  case "$(uname -m)" in
    arm64 | aarch64) echo aarch64 ;;
    x86_64 | amd64) echo x86_64 ;;
    *) uname -m ;;
  esac
}

# 找能链接该 musl target 的 C 编译器；找不到就返回非 0，由调用方决定 skip 还是 fail。
musl_cc_for() {
  local target="$1" arch="${1%%-*}" candidate candidates
  candidates=()
  [ -n "${MUSL_CROSS_DIR:-}" ] && candidates+=("${MUSL_CROSS_DIR}/bin/${arch}-linux-musl-gcc")
  candidates+=("${arch}-linux-musl-gcc" "${target}-gcc")
  # 裸 `musl-gcc`（musl-tools）只为**本机架构**服务：x86_64 机器上的 musl-gcc
  # 编不出 aarch64 目标，认下来就会得到一个链接期的诡异错误（而不是清晰的提示）。
  if [ "$(uname -s)" = "Linux" ] && [ "$arch" = "$(host_arch)" ]; then
    candidates+=(musl-gcc)
  fi
  for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

musl_hint() {
  local target="$1" arch="${1%%-*}"
  cat >&2 <<EOF
   需要能链接 ${target} 的 musl C 工具链，三选一：
     Linux : sudo apt-get install -y musl-tools        # 提供 musl-gcc（仅本机架构）
     macOS : brew install filosottile/musl-cross/musl-cross
     任意  : curl -LO https://musl.cc/${arch}-linux-musl-cross.tgz && tar xzf ${arch}-linux-musl-cross.tgz
             然后 MUSL_CROSS_DIR=\$PWD/${arch}-linux-musl-cross scripts/build-release.sh
   注：aws-lc-sys 与 bundled SQLite 都是 C 代码，交叉编译必须有目标 C 编译器，光 rustup
   target add 是不够的。
EOF
}

# 断言产物真的是静态 ELF。返回 0 表示通过。
#
# ⚠️ `file` 的措辞分两种，**两种都合格**：aarch64-musl 出 `statically linked`，
# 而 x86_64-musl 上 Rust 默认开 PIE，出的是 `static-pie linked`（自搬移、同样不需要
# 动态加载器）。2026-09-28 实测：只认 `statically linked` 会把 x86_64 的**合格**产物
# 判成失败。所以真正的判据是下面 readelf 那两条（无 PT_INTERP、无 NEEDED）——
# `file` 只当快速信号。
assert_static_elf() {
  local bin="$1" target="$2" desc readelf="" candidate
  desc="$(file -b "$bin")"
  case "$desc" in
    *"statically linked"* | *"static-pie linked"*) ;;
    *)
      echo "!!! ${bin} 不是静态链接：${desc}" >&2
      return 1
      ;;
  esac
  for candidate in readelf "${target%%-*}-linux-musl-readelf" "${target}-readelf" llvm-readelf; do
    if command -v "$candidate" >/dev/null 2>&1; then
      readelf="$candidate"
      break
    fi
  done
  if [ -n "$readelf" ]; then
    if "$readelf" -l "$bin" 2>/dev/null | grep -q 'INTERP'; then
      echo "!!! ${bin} 仍有 PT_INTERP（运行时需要动态加载器）" >&2
      return 1
    fi
    if "$readelf" -d "$bin" 2>/dev/null | grep -q 'NEEDED'; then
      echo "!!! ${bin} 仍有 NEEDED 动态依赖：" >&2
      "$readelf" -d "$bin" | grep 'NEEDED' >&2
      return 1
    fi
  else
    echo "    （未找到 readelf，只按 file(1) 判定静态性）"
  fi
  return 0
}

# 打包：bin/ + 部署资产 + 示例配置 + 校验和。顶层留一层目录，解包即一个自洽的目录树
# （原来把三个二进制平铺在包根，scp 解包时会散在宿主机当前目录里）。
package() {
  local target="$1" tarball="$2" stage name
  name="home-llm-gateway-${VERSION}-${target}"
  stage="$(mktemp -d)"
  mkdir -p "${stage}/${name}/bin" "${stage}/${name}/deploy"
  cp "target/${target}/release/gateway" "target/${target}/release/agent" \
    "target/${target}/release/mock-llm" "${stage}/${name}/bin/"
  cp deploy/agent.service deploy/gateway.service deploy/logrotate.example "${stage}/${name}/deploy/"
  cp gateway_config.example.yml agent_config.example.yml "${stage}/${name}/"
  (
    cd "${stage}/${name}"
    sha256_lines bin/* >SHA256SUMS
  )
  tar -C "$stage" -czf "$tarball" "$name"
  rm -rf "$stage"
}

# 用函数而不是把命令名存进变量：`$(sha256_cmd)` 会得到 "shasum -a 256" 这样一个
# 带空格的词，`"$(...)" bin/*` 会当成单条命令去执行，必然 127。
sha256_lines() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

failed=()
built=()
skipped=()

for target in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    if [ "$STRICT" -eq 1 ]; then
      echo "!!! ${target} 未安装（rustup target add ${target}）" >&2
      failed+=("$target")
    else
      echo "==> skip ${target}（未安装，可执行 rustup target add ${target}）"
      skipped+=("$target")
    fi
    continue
  fi

  # bash 3.2（macOS 自带）下空数组展开会让 `set -u` 直接报 unbound variable，
  # 所以 envs 先声明再赋值，执行处再判空。
  declare -a envs
  envs=()
  if [[ "$target" == *-linux-musl ]]; then
    cc="$(musl_cc_for "$target")" || {
      if [ "$STRICT" -eq 1 ]; then
        echo "!!! ${target} 缺少交叉 C 工具链" >&2
        musl_hint "$target"
        failed+=("$target")
      else
        echo "==> skip ${target}（缺少交叉 C 工具链）"
        musl_hint "$target"
        skipped+=("$target")
      fi
      continue
    }
    underscored="${target//-/_}"
    upper="$(echo "$target" | tr '[:lower:]-' '[:upper:]_')"
    envs+=("CC_${underscored}=${cc}" "CARGO_TARGET_${upper}_LINKER=${cc}")
    if command -v "$(dirname "$cc")/${target%%-*}-linux-musl-ar" >/dev/null 2>&1; then
      envs+=("AR_${underscored}=$(dirname "$cc")/${target%%-*}-linux-musl-ar")
    fi
    echo "==> build ${target} (release, cc=${cc})"
  else
    echo "==> build ${target} (release)"
  fi

  if [ "${#envs[@]}" -gt 0 ]; then
    build_ok=1
    env "${envs[@]}" cargo build --release --target "$target" \
      --bin gateway --bin agent --bin mock-llm || build_ok=0
  else
    build_ok=1
    cargo build --release --target "$target" --bin gateway --bin agent --bin mock-llm || build_ok=0
  fi
  if [ "$build_ok" -eq 0 ]; then
    echo "!!! build ${target} 失败，继续后面的目标" >&2
    failed+=("$target")
    continue
  fi

  if [ "$VERIFY" -eq 1 ] && [[ "$target" == *-linux-musl ]]; then
    ok=1
    for bin in gateway agent mock-llm; do
      assert_static_elf "target/${target}/release/${bin}" "$target" || ok=0
    done
    if [ "$ok" -eq 0 ]; then
      echo "!!! ${target} 静态性断言失败" >&2
      failed+=("$target")
      continue
    fi
    echo "    ✔ 三个二进制都是静态链接（file + readelf 已核）"
  fi

  tarball="${DIST}/home-llm-gateway-${VERSION}-${target}.tar.gz"
  if package "$target" "$tarball"; then
    echo "    -> ${tarball}"
    built+=("$target")
  else
    echo "!!! 打包 ${target} 失败，继续后面的目标" >&2
    failed+=("$target")
  fi
done

if [ "${#built[@]}" -gt 0 ]; then
  (
    cd "$DIST"
    for t in "${built[@]}"; do
      sha256_lines "home-llm-gateway-${VERSION}-${t}.tar.gz"
    done >SHA256SUMS
  )
  echo "==> 校验和：${DIST}/SHA256SUMS"
fi

if [ "${#failed[@]}" -gt 0 ]; then
  echo "完成（有失败）：成功 ${#built[@]} 个目标，失败 ${#failed[@]} 个：${failed[*]}" >&2
  exit 1
fi

# S2-11：一个目标都没构建成功时 `dist/` 是空的，这**不是**成功。原来只判 `failed` 非空，
# 于是 rustup 不在 PATH / 一个 target 都没装时会打印"完成（0 个目标）"并 exit 0——调用方
# （CI、部署脚本）拿到 0 却什么都拿不到。
if [ "${#built[@]}" -eq 0 ]; then
  echo "!!! 没有任何目标构建成功（跳过 ${#skipped[@]} 个未就绪目标：${skipped[*]-}）；dist/ 是空的" >&2
  echo "    先 rustup target add <triple>，并确认交叉 C 工具链可用（见上面的提示）" >&2
  exit 1
fi

if [ "${#skipped[@]}" -gt 0 ]; then
  echo "完成（${#built[@]} 个目标）；跳过 ${#skipped[@]} 个未就绪目标：${skipped[*]}"
else
  echo "完成（${#built[@]} 个目标），产物在 ${DIST}/"
fi
