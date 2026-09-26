//! 入口认证与限流：把「谁在调用」和「还能不能调用」从请求处理里分出来。
//!
//! 单独成模块的理由与 [`crate::openai`] 相同——**消费者跨越了代理层的边界**：路由层的
//! `/v1/models`（网关自己聚合回答，没有上游可转发）也要走同一套认证与限流。放在 `proxy`
//! 里，等于让路由层反向依赖代理层。
//!
//! 这里同时收掉了原先的两份实现：`proxy` 内联复制过一遍认证+限流（因为它还需要
//! `key_id`/`key_name` 记账，而旧 helper 把它们丢掉了）。现在两条路径都走
//! [`authenticate`]，401/429 的文案与顺序只存在一处。

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::openai::{error_response, rate_limited};
use crate::state::AppState;
use tracing::warn;

/// 已通过认证的调用方身份。
///
/// **不含明文 token**（评估记录 P2-19）：限流桶按 [`Self::key_id`] 作键，明文只在与
/// keystore 校验的那一刻存在于栈上。把它留在这里等于给每个 handler 一个把凭据写进日志 /
/// 指标标签 / 错误响应的机会，而 keystore 那边是"只存哈希、明文不落盘"的姿态。
pub struct AuthenticatedKey {
    /// 用量计量的归属（`/admin/usage` 按它聚合），也是限流桶的键。
    pub key_id: String,
    pub key_name: String,
}

/// 认证 / 限流被拒的原因。
///
/// **刻意做小**：`Response`（`hyper::Response<axum::body::Body>`）是 128+ 字节，把它塞进
/// `Err` 会让 `Result` 连 Ok 路径都要搬这么大一块，clippy 的 `result_large_err` 会报
/// （CI 用的 stable 比本机 1.97 新，是它先发现的）。所以这里只留原因，响应交给
/// [`AuthRejection::into_response`] 生成——顺带把两条文案收在一处。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRejection {
    /// 缺少 / 无效的 Bearer key → 401。
    InvalidKey,
    /// 超过该 key 的每分钟配额 → 429，带**按回填速度算出的** `Retry-After`（复扫 A4：
    /// 不再是写死的 60s，见 [`crate::ratelimit::RateLimiter::retry_after_secs`]）。
    RateLimited { retry_after_secs: u64 },
}

impl AuthRejection {
    /// 生成给客户端的响应。**状态码、`error.type` 与文案只在这里定义。**
    pub fn into_response(self) -> Response {
        match self {
            AuthRejection::InvalidKey => {
                error_response(StatusCode::UNAUTHORIZED, "invalid or missing API key")
            }
            AuthRejection::RateLimited { retry_after_secs } => {
                rate_limited("rate limit exceeded", retry_after_secs)
            }
        }
    }
}

/// 认证 + 限流：通过返回身份，否则返回拒绝原因。
///
/// 返回 `Result` 而不是 `Option`/`bool`，是为了让"认证没过却继续往下走"写不出来：
/// 拿不到 [`AuthenticatedKey`]，唯一能做的就是处理那个 `Err`。
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedKey, AuthRejection> {
    let Some(key) = verify_api_key(state, headers).await else {
        return Err(AuthRejection::InvalidKey);
    };
    if let Some(rl) = &state.rate_limiter {
        // 桶键是 key id，**不是明文 token**（P2-19）：限流器只增不减，拿明文作键等于把它
        // 常驻进程内存（`/proc/<pid>/mem`、core dump 都带着它）。同一条身份对同一个桶
        // 的映射不受影响——id 与 token 一一对应。
        if !rl.try_acquire(&key.key_id) {
            return Err(AuthRejection::RateLimited {
                retry_after_secs: rl.retry_after_secs(),
            });
        }
    }
    Ok(key)
}

/// 从 `Authorization` 头里取出 Bearer 凭据（`/v1` 认证与 `/admin` 鉴权共用这一套解析）。
///
/// 规范（RFC 9110 §11.1）：scheme 名**大小写不敏感**，scheme 与凭据之间是 `1*SP`
/// （一个或多个空格）。旧实现 `strip_prefix("Bearer ")` 是字节精确匹配，`bearer sk-…`
/// 这种完全合法的请求会拿到 401——与"OpenAI 兼容"的目标相悖（P3-17）。
///
/// 放宽的只有"scheme 大小写"与"分隔空格"这两件事，**不**放宽 scheme 名本身：`Bearerx`
/// 是另一个 token，`Token` / `Basic` 更不是 Bearer，一律 `None`。空凭据同样 `None`，
/// 不会拿空串去和 keystore（或 admin token）比对。
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, credentials) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = credentials.trim_start_matches(' ');
    (!token.is_empty()).then_some(token)
}

async fn verify_api_key(state: &AppState, headers: &HeaderMap) -> Option<AuthenticatedKey> {
    let token = bearer_token(headers)?.to_string();
    let store = state.key_store.clone();
    // 明文 token 移动进校验任务（不 clone）：它是这段代码里唯一持有明文的地方，
    // 任务结束即释放。
    let record = match tokio::task::spawn_blocking(move || store.authorize_record(&token)).await {
        Ok(rec) => rec?,
        Err(e) => {
            // 校验任务 panic/被取消：按认证失败处理，不放行
            warn!("key verification task failed: {e}");
            return None;
        }
    };
    Some(AuthenticatedKey {
        key_id: record.id,
        key_name: record.name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metrics::Metrics, options::Options, registry::Registry, storage::KeyStore};

    /// 规格（评估记录 P2-19）：限流桶必须按 **[`KeyRecord::id`]** 作键，**不能**按明文 token。
    ///
    /// 明文 key 只应活在认证那一刻的栈上：keystore 自己只留 sha256（索引）+ argon2（校验），
    /// 而限流器的桶表是**长生命周期的内存状态**。按明文作键，等于把每一个用过的 key 常驻
    /// 进程内存直到退出，并且随 key 轮换 / 吊销无上限增长——这与"明文不落盘"的姿态自相矛盾
    /// （`/proc/<pid>/mem`、core dump、panic 报告都会带上它）。
    ///
    /// [`KeyRecord::id`]: crate::storage::KeyRecord
    #[tokio::test]
    async fn the_rate_limiter_keys_buckets_by_key_id_not_by_the_plaintext_token() {
        let opts = Options {
            rate_limit_per_min: 60,
            ..Options::default()
        };
        let store = KeyStore::new(None);
        let created = store.create("p2-19".into()).expect("建 key 应当成功");
        let state = AppState::new(Registry::default(), store, Metrics::default(), &opts);

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {}", created.plaintext)).unwrap(),
        );

        let identity = authenticate(&state, &headers).await.expect("认证应当通过");
        assert_eq!(
            identity.key_id,
            created.record.id(),
            "前提：身份里的 key_id 来自 keystore"
        );

        let rl = state
            .rate_limiter
            .as_ref()
            .expect("前提：60/min 应当建出限流器");
        assert_eq!(
            rl.bucket_keys(),
            vec![created.record.id().to_string()],
            "限流桶必须按 key id 作键"
        );
        assert!(
            !rl.bucket_keys()
                .iter()
                .any(|k| k.contains(&created.plaintext)),
            "明文 token 不得作为桶键常驻内存"
        );
    }

    /// 规格：两种拒绝的状态码 / `error.type` / `Retry-After` 必须与拆分前**逐字一致**。
    ///
    /// SDK 按 `error.type` 决定是否自动重试（429 重试、401 不重试），脚本按 `Retry-After`
    /// 退避——这条把 `into_response` 这张映射表钉住，因为响应构造现在只在这一处。
    #[tokio::test]
    async fn rejection_maps_to_the_same_response_as_before() {
        for (rejection, status, ty, challenge) in [
            (
                AuthRejection::InvalidKey,
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                Some("Bearer"),
            ),
            (
                AuthRejection::RateLimited {
                    retry_after_secs: 7,
                },
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                None,
            ),
        ] {
            let resp = rejection.into_response();
            assert_eq!(resp.status(), status);
            assert_eq!(
                resp.headers().contains_key(axum::http::header::RETRY_AFTER),
                status == StatusCode::TOO_MANY_REQUESTS,
                "只有 429 带 Retry-After"
            );
            // 而且必须是**调用方给出的那个值**（复扫 A4：不再编造 60s）
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
                (status == StatusCode::TOO_MANY_REQUESTS).then_some("7"),
                "429 的 Retry-After 必须原样带上调用方算出的值"
            );
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok()),
                challenge,
                "401 必须给出 authentication challenge（RFC 9110 §15.5.2）；429 不是认证失败，不带"
            );
            let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["error"]["type"], ty);
        }
    }

    /// 规格（P3-17）：`Authorization` 的 scheme 名**大小写不敏感**，且 scheme 与凭据之间
    /// 允许**一个或多个空格**（RFC 9110 §11.1：`credentials = auth-scheme [ 1*SP ... ]`）。
    ///
    /// 旧实现 `strip_prefix("Bearer ")` 是字节精确匹配，下面除第一行外每一行都拿到 401；
    /// 而 OpenAI 官方接口接受小写 scheme——"兼容"就该有这一条。
    #[tokio::test]
    async fn the_bearer_scheme_is_case_insensitive_and_spacing_tolerant() {
        let store = KeyStore::new(None);
        let created = store.create("p3-17".into()).expect("建 key 应当成功");
        let state = AppState::new(
            Registry::default(),
            store,
            Metrics::default(),
            &Options::default(),
        );

        for header in [
            format!("Bearer {}", created.plaintext),   // 现状：回归项
            format!("bearer {}", created.plaintext),   // 小写
            format!("BEARER {}", created.plaintext),   // 大写
            format!("BeArEr {}", created.plaintext),   // 混合
            format!("Bearer   {}", created.plaintext), // 1*SP：多空格
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&header).unwrap(),
            );
            let identity = authenticate(&state, &headers)
                .await
                .unwrap_or_else(|_| panic!("`{header}` 应当认证通过"));
            assert_eq!(
                identity.key_id,
                created.record.id(),
                "`{header}` 应当认出同一把 key"
            );
        }
    }

    /// 规格（P3-17）：放宽大小写**不等于**放宽 scheme。`Bearerx` 是另一个 token，`Token`
    /// / `Basic` 更不是 Bearer；空凭据 / 缺凭据也不该走到 keystore 比较。
    #[tokio::test]
    async fn a_non_bearer_scheme_is_still_rejected() {
        let store = KeyStore::new(None);
        let created = store.create("p3-17-neg".into()).expect("建 key 应当成功");
        let state = AppState::new(
            Registry::default(),
            store,
            Metrics::default(),
            &Options::default(),
        );

        for header in [
            format!("Bearerx {}", created.plaintext),
            format!("bearerx {}", created.plaintext),
            format!("Token {}", created.plaintext),
            format!("Basic {}", created.plaintext),
            format!("Bearer{}", created.plaintext), // 没有分隔空格
            "Bearer ".to_string(),                  // 空凭据
            "Bearer".to_string(),                   // 只有 scheme
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&header).unwrap(),
            );
            assert!(
                authenticate(&state, &headers).await.is_err(),
                "`{header}` 不该通过认证"
            );
        }
    }
}
