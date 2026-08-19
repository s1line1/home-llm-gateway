//! Admin API：运行时签发 / 列出 / 吊销 API Key。
//! 所有 /admin/* 请求都需要 `Authorization: Bearer <--admin-token>`。

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::http::AppState;
use crate::keystore::constant_time_eq;

/// Admin 鉴权中间件：仅放行持有 admin token 的请求。
pub async fn admin_auth(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let expected = state.admin_token.as_deref().unwrap_or_default();
    let ok = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| constant_time_eq(expected.as_bytes(), t.as_bytes()))
        .unwrap_or(false);
    if ok {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "message": "invalid admin token", "type": "auth_error" } })),
    )
        .into_response()
}

/// 列出所有动态 key（只展示前缀，不暴露明文）。
pub async fn list_keys(State(state): State<AppState>) -> Json<serde_json::Value> {
    let out: Vec<serde_json::Value> = state
        .key_store
        .list()
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "created_at": r.created_at,
                "enabled": r.enabled,
                "prefix": format!("{}…", &r.key[..r.key.len().min(12)]),
            })
        })
        .collect();
    Json(json!(out))
}

/// 创建 key，返回明文（仅此一次展示）。
pub async fn create_key(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed")
        .to_string();
    if name.chars().count() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "message": "name too long", "type": "invalid_request" } })),
        )
            .into_response();
    }
    let rec = state.key_store.create(name);
    (
        StatusCode::CREATED,
        Json(json!({
            "id": rec.id,
            "key": rec.key,
            "name": rec.name,
            "created_at": rec.created_at,
            "enabled": rec.enabled,
        })),
    )
        .into_response()
}

/// 吊销 key。
pub async fn delete_key(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if state.key_store.delete(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "message": "key not found", "type": "not_found" } })),
        )
            .into_response()
    }
}

/// 管理页面（GET /）：浏览器打开网关地址即可管理 API Key。
/// 页面本身不鉴权，所有数据操作经由带 admin token 的 /admin/keys API。
pub async fn admin_page() -> Html<&'static str> {
    Html(ADMIN_PAGE)
}

const ADMIN_PAGE: &str = r#"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home LLM Gateway</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; line-height: 1.6; }
  h1 { font-size: 1.4rem; }
  input, button { font-size: 14px; padding: 6px 10px; margin: 4px 0; }
  input[type=password], input[type=text] { width: 260px; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #ddd; font-size: 13px; }
  code { background: rgba(128,128,128,.15); padding: 1px 5px; border-radius: 4px; word-break: break-all; }
  .msg { color: #0a7; }
  .err { color: #c33; }
  .muted { color: #888; font-size: 12px; }
  .ok { color: #0a7; font-weight: 600; }
  .bad { color: #c33; font-weight: 600; }
  button.danger { background: #c33; border: 1px solid #c33; color: #fff; }
  button.danger:hover { background: #a22; }
</style>
</head>
<body>
<h1>Home LLM Gateway</h1>
<p id="health" class="muted">加载中…</p>

<section>
  <h2>管理员登录</h2>
  <p class="muted">输入启动网关时的 <code>--admin-token</code>，保存在本浏览器（localStorage）。</p>
  <input id="token" type="password" placeholder="Admin Token">
  <button id="save">保存并加载</button>
</section>

<section>
  <h2>API Keys</h2>
  <form id="create">
    <input id="name" type="text" placeholder="用途，如 dsh-client" maxlength="64">
    <button type="submit">创建 Key</button>
  </form>
  <div id="created"></div>
  <h3>已有 Keys <button id="refresh">刷新</button></h3>
  <table>
    <thead><tr><th>名称</th><th>ID</th><th>前缀</th><th>创建时间</th><th>状态</th><th></th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
</section>

<script>
const TOKEN_KEY = "hlmg.admin.token";
let token = localStorage.getItem(TOKEN_KEY) || "";
document.getElementById("token").value = token;

const healthEl = document.getElementById("health");
fetch("/healthz").then(r => r.text()).then(t => {
  healthEl.textContent = "网关状态: " + t + " · " + new Date().toLocaleString();
}).catch(() => { healthEl.textContent = "网关状态: 无法连接"; });

function show(el, text, isErr) {
  el.textContent = text;
  el.className = isErr ? "err" : "msg";
}

async function api(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ "Authorization": "Bearer " + token }, opts.headers || {});
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = "HTTP " + r.status;
    try { msg = (await r.json()).error.message || msg; } catch (e) {}
    throw new Error(msg);
  }
  return r.status === 204 ? null : r.json();
}

document.getElementById("save").onclick = () => {
  token = document.getElementById("token").value.trim();
  localStorage.setItem(TOKEN_KEY, token);
  refresh();
};

const createdEl = document.getElementById("created");
document.getElementById("create").onsubmit = async (e) => {
  e.preventDefault();
  const name = document.getElementById("name").value.trim() || "unnamed";
  try {
    const rec = await api("/admin/keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    createdEl.innerHTML = "已创建 <code>" + rec.key + "</code> <button onclick='navigator.clipboard.writeText(\"" + rec.key + "\")'>复制</button> <span class=\"muted\">（仅显示这一次）</span>";
    document.getElementById("name").value = "";
    refresh();
  } catch (err) { show(createdEl, err.message, true); }
};

document.getElementById("refresh").onclick = refresh;

async function refresh() {
  const rows = document.getElementById("rows");
  rows.innerHTML = "";
  try {
    const keys = await api("/admin/keys");
    if (!keys.length) { rows.innerHTML = "<tr><td colspan='6' class='muted'>暂无动态 key（静态 key 在 --api-keys 中配置）</td></tr>"; return; }
    for (const k of keys) {
      const tr = document.createElement("tr");
      const when = new Date(k.created_at * 1000).toLocaleString();
      tr.innerHTML = "<td>" + escapeHtml(k.name) + "</td><td><code>" + k.id + "</code></td><td><code>" + k.prefix + "</code></td><td>" + when + "</td>" +
        "<td class=\"" + (k.enabled ? "ok" : "bad") + "\">" + (k.enabled ? "启用" : "禁用") + "</td>" +
        "<td><button class=\"danger\" data-id=\"" + k.id + "\" data-name=\"" + escapeHtml(k.name) + "\">吊销</button></td>";
      rows.appendChild(tr);
    }
    rows.querySelectorAll("button").forEach(b => b.onclick = () => revoke(b.dataset.id, b.dataset.name));
  } catch (err) {
    rows.innerHTML = "<tr><td colspan='6' class='err'>" + escapeHtml(err.message) + "</td></tr>";
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
}

async function revoke(id, name) {
  if (!confirm("吊销 key: " + name + " (" + id + ")？立即生效，不可恢复。")) return;
  try {
    await api("/admin/keys/" + id, { method: "DELETE" });
    refresh();
  } catch (err) {
    alert(err.message);
  }
}

refresh();
</script>
</body>
</html>"#;
