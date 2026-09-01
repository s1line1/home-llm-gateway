//! metrics 场景 e2e 测试。

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_metrics_endpoint() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let (gw, agent, base, key) = start_stack(Duration::from_secs(10), 0, 4, None).await;
    let client = reqwest::Client::new();

    // 先发两个请求（一个 401、一个 200），让计数器有值
    let _ = client
        .get(format!("{base}/v1/models"))
        .send()
        .await
        .unwrap();
    let _ = client
        .get(format!("{base}/v1/models"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();

    let resp = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("hlmg_requests_total{status=\"401\"} 1"),
        "missing 401 counter: {text}"
    );
    assert!(
        text.contains("hlmg_requests_total{status=\"200\"} 1"),
        "missing 200 counter: {text}"
    );
    assert!(
        text.contains("hlmg_agents 1"),
        "missing agents gauge: {text}"
    );
    assert!(
        text.contains("hlmg_quic_connections 1"),
        "missing quic connections gauge: {text}"
    );
    assert!(
        text.contains("hlmg_agent_connections_total "),
        "missing agent connections counter: {text}"
    );
    assert!(
        text.contains("hlmg_bytes_out "),
        "missing bytes counter: {text}"
    );

    agent.shutdown().await;
    gw.shutdown().await;
}
