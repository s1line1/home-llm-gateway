#!/usr/bin/env python3
"""记录↔代码一致性检查（可复跑）。

为什么需要它：本仓库的登记表（`docs/PROJECT_SCAN.md`、`docs/SUPPORT_LAYER_RAW_FINDINGS.md`）
是**手写的**，条目里大量写着 `path:line` 指针与「已修(<commit>)」声明。2026-09-23 的全量审计
发现两类漂移是**机械可查**的：

  ① 指针漂移：文件被重命名/搬走，或行号越界（重构后 PR 里最常见）；
  ② 提交声明不实：写「已修(abc1234)」而那个 hash 根本不存在（或不是提交）。

两件都只查**存在性**，不查**内容**：指针指向的那一行还在、但早已与本条无关时，这里照样报绿
（2026-09-24 二轮审计实测：`P1-5` 的 `storage/mod.rs:572` 现在是段无关代码，`P3-1` 的
`proto/src/lib.rs:11` 落在注释里而常量已被顶到 `:21`）。所以"0 漂移"只保证指针能解析、行号不越界。

**唯一的内容检查是一条廉价的启发式**（2026-10-07 加）：**已跟踪**记录里 `.rs` 的**单行**指针
若落在空行或纯 `})];,` 上，直接判漂——这种指针指的显然不是一句可读代码。（范围指针不查：它的
结束行天然常是 `}`。）它能抓到"文件存在、行号也不越界、但指的已是别处"的一大类，实测一次抓出
16 处：7 处在已跟踪文档，9 处在 `docs/` 草稿。
**它只对仓库里的记录生效**（见 `tracked_paths`）：`docs/*` 是维护者本机的草稿，别人改不到，
不该让一份草稿把所有 PR 的 hook 判红。存在性与行号越界两项则照旧扫整个 `DOCS`。

这个脚本也**不判断"是否真的修好了"**（那要人读代码）。扫描范围就是下面 `DOCS` 列出的文件。

**谁在跑它**（重扫 H1-5 补齐）：`make check-records`（已挂进 `make check` 的前置）与
`.git/hooks/pre-commit`。**CI 上没有它。**

⚠️ **扫描范围决定它在哪里生效**（2026-10-07 厘清）：`DOCS` 原先只有
`docs/PROJECT_SCAN.md` 与 `docs/SUPPORT_LAYER_RAW_FINDINGS.md`，而这两份**不在仓库里**
（`.gitignore` 的 `/docs/*`）⇒ 任何**新检出**（CI 或新同学）里脚本只会打印"跳过（不存在）"
然后 exit 0，**等于空转**。现在 `DOCS` 另加了四份**已跟踪**的登记表——`TODO.md`、
`OPTIMIZATION.md`、`REBUILD.md`、`EDGE_REBRAND.md`——它们在新检出里也**存在**，
所以这几份是这套检查里**唯一能在任何工作树上真正生效**的覆盖（挂不挂进 CI 都成立）。
没有 python3 时 hook 会明确打印"跳过"而不是静默通过。

用法：
    python3 scripts/check-records.py            # 检查并打印摘要；有漂移则 exit 1
    python3 scripts/check-records.py --verbose  # 列出每一条漂移
    make check-records                          # 同上（门禁里的那一步）
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# 仓库真正的一级目录：用来区分「crate 根相对路径」（`proto/src/lib.rs`）与「别人的源码路径」
# （`server/conn/http1.rs` 是 hyper 内部的路径，在记录里被跨行折断了）。
REPO_TOP_LEVEL = {p.name for p in ROOT.iterdir() if p.is_dir()} | {".github", ".config", ".tmp"}
DOCS = [
    ROOT / "docs/PROJECT_SCAN.md",
    ROOT / "docs/SUPPORT_LAYER_RAW_FINDINGS.md",
    # 下面几份是**已跟踪**的登记表。与上两份不同，它们在 CI 的新检出里也存在，
    # 所以是这套检查里唯一**能在 CI 生效**的覆盖（见文件头的"谁在跑它"）。
    ROOT / "TODO.md",
    ROOT / "OPTIMIZATION.md",
    ROOT / "REBUILD.md",
    ROOT / "EDGE_REBRAND.md",
]

# `path/to/file.rs:123` 或 `path/to/file.rs:123-140`（也接受 `:123,456` 这种行号列表）
POINTER = re.compile(r"`?([A-Za-z0-9_./-]+\.(?:rs|ts|tsx|js|mjs|py|sh|toml|yml|yaml|json|md)):(\d+)(?:[-,](\d+))?")
# 这些前缀说明"这个指针是**引用历史**用的"（例如「记录写 `a.rs:64` → 现在 `:73`」），
# 不是对当前代码的断言，跳过它们，否则脚本会被自己的漂移叙事喂成一片红。
QUOTED_HISTORY = re.compile(
    r"(记录写|原记录|原文写|原先|漂移|旧的|旧指针|历史|已失效|失效|已变|已不|不再|is now|no longer)[^\n]{0,24}$"
)
# §四「TODO 对账结果」里有一张 `| 条目 | 旧指针 | 新位置 |` 表：那一列**本来就是**旧指针，
# 是记录在展示漂移而不是在断言现状，所以显式豁免（用指针文本而非行号，行号会漂）。
HISTORICAL_POINTERS = {
    "gateway/src/lib.rs:175",
    "lib.rs:290",
    # 同理：「`Storage::authorize_id`（**原** `storage/mod.rs:210`）」是历史位置。
    "storage/mod.rs:210",
}
# §五「文档/配置漂移清单」本身就是一份"旧指针清单"，整段跳过（按小节标题界定）。
# 只有那两份登记表有这个结构，所以**按文档名限定**，别让它误伤其他文档。
SKIP_SECTION = {"PROJECT_SCAN.md": ("## 五、", "## 六、")}
# 「已修(<hash>)」「修复提交 <hash>」「commit <hash>」「提交 <hash>」「(<hash> 修好)」
COMMIT = re.compile(r"(?:已修|修复提交|提交|commit|修好)[^\n]{0,20}?\b([0-9a-f]{7,40})\b")
HEXLIKE = re.compile(r"^[0-9a-f]{7,40}$")
# 这些 hash **不是本仓库的提交声明**，是别的东西的版本串，不该当提交查。
# `8bab26f4f` 来自 `rustc --version`（`rustc 1.97.1 (8bab26f4f 2026-07-14)`），
# 是编译器自己的构建 hash；扩展扫描范围后它第一次被误抓，故显式豁免。
NOT_A_REPO_COMMIT = {"8bab26f4f"}


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )


def commit_exists(sha: str) -> bool:
    return git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def tracked_paths() -> set[str]:
    """仓库里被跟踪的文件（相对 POSIX 路径）。

    内容检查只对它们生效。`docs/*` 在 `.gitignore` 里，那是**维护者本机的审计草稿**：
    它漂不漂由维护者自己看着办，而且任何人都改不到（进不了提交），所以不该在这里判失败——
    否则一份本机草稿就能让所有 PR 的 hook 变红。
    """
    return set(git("ls-files").stdout.splitlines())


def repo_index() -> dict[str, list[Path]]:
    """仓库内所有文件，按"路径后缀"建索引。

    记录里的指针写法不统一：有的从仓库根写（`crates/proto/src/lib.rs`），有的从 **crate 根**写
    （`proto/src/lib.rs`、`storage/mod.rs`）。所以除了直接解析，还要按后缀唯一匹配一次。
    """
    index: dict[str, list[Path]] = {}
    skip = {".git", "target", "node_modules", ".cargo-home", ".tmp", "dist"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or skip & set(path.parts):
            continue
        rel = path.relative_to(ROOT).as_posix()
        for cut in range(len(rel.split("/"))):
            suffix = "/".join(rel.split("/")[cut:])
            index.setdefault(suffix, []).append(path)
    return index


def looks_external(raw: str) -> bool:
    """依赖源码里的路径（`rusqlite-0.40.2/src/…`、`rustls/src/…`）本仓库当然没有，跳过。"""
    return bool(re.search(r"-\d+\.\d+\.\d+", raw)) or raw.startswith(("rustls/", "hyper-", "tokio-"))


def resolve(raw: str, index: dict[str, list[Path]]) -> tuple[Path | None, str]:
    """解析指针路径：直接命中 → 后缀唯一命中 → 外部依赖 → 找不到。"""
    direct = ROOT / raw
    if direct.exists():
        return direct, "ok"
    if looks_external(raw):
        return None, "external"
    hits = index.get(raw, [])
    if len(hits) == 1:
        return hits[0], "ok"
    if len(hits) > 1:
        return None, "ambiguous"
    # 索引里也找不到：以仓库一级目录开头 = 真·指针失效；否则当别人的源码路径
    # （例如 hyper 的 `server/conn/http1.rs`，在记录里被跨行折断了）。
    if raw.split("/")[0] not in REPO_TOP_LEVEL:
        return None, "external"
    return None, "missing"


def line_count(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def main() -> int:
    verbose = "--verbose" in sys.argv
    pointer_drift: list[str] = []
    commit_drift: list[str] = []
    checked_pointers = checked_commits = external_refs = 0
    index = repo_index()
    tracked = tracked_paths()

    for doc in DOCS:
        if not doc.exists():
            print(f"跳过（不存在）：{doc}")
            continue
        # 内容检查只对**仓库里**的记录生效；见 `tracked_paths` 的说明。
        content_check = doc.relative_to(ROOT).as_posix() in tracked
        skip_section = SKIP_SECTION.get(doc.name)
        in_skip_section = False
        for lineno, line in enumerate(doc.read_text().splitlines(), start=1):
            if skip_section and line.startswith(skip_section[0]):
                in_skip_section = True
            elif skip_section and line.startswith(skip_section[1]):
                in_skip_section = False
            if in_skip_section:
                continue
            for raw_path, first, last in POINTER.findall(line):
                if QUOTED_HISTORY.search(line[: line.index(raw_path)]):
                    continue
                if f"{raw_path}:{first}" in HISTORICAL_POINTERS:
                    continue
                if "/" not in raw_path:
                    continue  # 只写文件名的指针（如 `lib.rs`）歧义太大，跳过
                target, how = resolve(raw_path, index)
                if how == "external":
                    external_refs += 1
                    continue
                if target is None:
                    if how == "ambiguous":
                        pointer_drift.append(
                            f"{doc.name}:{lineno} → 指针 `{raw_path}` 有多处匹配，需写全路径"
                        )
                    else:
                        pointer_drift.append(
                            f"{doc.name}:{lineno} → 文件不存在 `{raw_path}`"
                        )
                    continue
                checked_pointers += 1
                want = int(last or first)
                total = line_count(target)
                if want > total:
                    pointer_drift.append(
                        f"{doc.name}:{lineno} → `{raw_path}:{want}` 越界（该文件只有 {total} 行）"
                    )
                elif content_check and not last and target.suffix == ".rs":
                    # 廉价的内容检查：**单行**指针落到空行或纯括号上，说明它指的显然不是
                    # 一句可读的代码（多半是重构后漂了）。范围指针（`a-b`）不查——它的结束行
                    # 天然常是 `}`。这条能抓到"文件在、行号也不越界、但指错了"的一大类。
                    #
                    # ⚠️ 这里必须用 `not last` 而不是 `last is None`：可选组未参与匹配时
                    # `re.findall` 给的是**空字符串**，不是 None（`int(last or first)` 两种都能吃，
                    # 但 `is None` 会让这条分支永远不执行——踩过一次）。
                    body = target.read_text(encoding="utf-8", errors="replace").splitlines()
                    here = body[want - 1].strip() if want else ""
                    if here == "" or all(ch in "})];," for ch in here):
                        pointer_drift.append(
                            f"{doc.name}:{lineno} → `{raw_path}:{want}` 落在空行/纯括号上，多半已漂"
                        )
            for sha in COMMIT.findall(line):
                if not HEXLIKE.match(sha) or sha in NOT_A_REPO_COMMIT:
                    continue
                checked_commits += 1
                if not commit_exists(sha):
                    commit_drift.append(f"{doc.name}:{lineno} → 提交 `{sha}` 不存在")

    print(
        f"检查了 {checked_pointers} 个文件指针、{checked_commits} 个提交声明"
        f"（另有 {external_refs} 处指向依赖源码，跳过）"
    )
    for label, rows in (("指针漂移", pointer_drift), ("提交声明不实", commit_drift)):
        print(f"  {label}: {len(rows)}")
        if verbose:
            for row in rows:
                print(f"    - {row}")
    if pointer_drift or commit_drift:
        print("不一致（用 --verbose 看明细）")
        return 1
    print("一致性检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
