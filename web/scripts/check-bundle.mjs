// 构建产物泄漏检查（PROJECT_SCAN P3-19 的后续）。
//
// JSX **子节点位置**的 `//` 注释不是注释、而是文本，会被原样渲染到页面上 —— 而 `tsc` 与
// `vite build` 都不会报错（那是合法 JSX 文本）。本仓库的注释习惯带 `（P<级别>-<编号>）`
// 这类审计标记，它们只该存在于源码里，于是构建后扫一遍产物：一旦出现这种标记，几乎可以
// 肯定有注释被当成了内容。
//
// 它是**启发式**的，只抓"带编号的审计标记"这一种特征；通用的"这段文本是不是注释泄漏"做不到。
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const DIST = new URL("../dist/", import.meta.url).pathname;
const MARKER = /\b(?:SL-)?P\d+-\d+\b/g;
const TEXT_EXT = /\.(?:js|mjs|css|html|map)$/;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

const hits = [];
for (const file of walk(DIST)) {
  if (!TEXT_EXT.test(file)) continue;
  const text = readFileSync(file, "utf8");
  for (const m of text.matchAll(MARKER)) hits.push(`${file}: ${m[0]}`);
}

if (hits.length > 0) {
  console.error("✘ web/dist 里出现了只该存在于源码注释里的审计标记：");
  for (const hit of hits.slice(0, 10)) console.error("  " + hit);
  console.error(`  共 ${hits.length} 处。最常见的原因：把 // 注释写在了 JSX 子节点位置（那里它是文本）。`);
  process.exit(1);
}
console.log("✔ 前端产物无注释泄漏标记");
