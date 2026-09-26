//! 启动期资源上限的 e2e 断言。
//!
//! 单测只能证明 `nofile::raise_to_target` 这个函数本身是对的；它证明不了
//! **`Gateway::start` 真的调用了它**。而"没调用"恰好是本仓库最危险的一类失败：
//! `install()` 是 `pub fn`，删掉调用没有任何编译警告、单测与 clippy 全绿，
//! 只有高并发时才会以 `Too many open files` 的形式冒出来。
//!
//! 所以这里起一套真实网关，然后读**进程自己**的 `/proc/self/limits` 核对实际生效额度——
//! 不以网关日志为准（日志是我们自己写的，写错也照样"通过"）。

use super::common::*;

/// 规格：**起一套网关之后，进程的 NOFILE 软上限必须已经达到目标值**（而不是 systemd 默认的 1024）。
///
/// 做法是先把本进程的 soft 手动降到 1024（复现云端 `gateway.service` 未设 `LimitNOFILE` 时的
/// 处境），再走生产路径起栈。
///
/// 平台差异：`/proc` 只有 Linux 有，macOS 上这一步会跳过；但"返回值必须是抬过/或本来就够高"
/// 的断言在任何 unix 上都跑，所以本用例在本机也有意义（能抓到"install 没被调用"）。
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_startup_raises_the_nofile_soft_limit_in_the_real_process() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let (original_soft, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();
    let target = hard.min(gateway::nofile::TARGET_SOFT_LIMIT);
    // 能不能**构造**出"启动前被压到 1024"这个场景。`target <= 1024` 时压根没什么可抬的（目标
    // 没超过 systemd 的默认值）——那是**逻辑上**不适用，不是环境问题。
    let can_reproduce = target > 1024;
    if can_reproduce {
        // 复扫 F4：这里以前写作 `can_reproduce && setrlimit(..).is_ok()`，把"压不下去"吞成
        // `false`，于是**最严格的那条断言（`soft == target`）被静默跳过**、用例照样报绿。
        // 既然 `target > 1024`，就有 hard ≥ target > 1024，而把 soft 降到 1024 在任何 unix 上
        // 都该被允许——压不下去说明环境有额外限制，那就该响，而不是装作跑过了。
        assert!(
            rlimit::setrlimit(rlimit::Resource::NOFILE, 1024, hard).is_ok(),
            "hard={hard} ≥ target={target} > 1024：把 soft 压到 1024 在任何 unix 上都该被允许；             失败会让最严格的那条断言被静默跳过（复扫 F4）"
        );
    }
    let soft_before = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap().0;

    let (gw, agent, _base, _key) = start_stack(4, |_| {}).await;

    // ① 网关自己报告的结论（必须与启动日志一致）
    let outcome = gw.nofile.outcome();
    match outcome {
        gateway::nofile::NoFileOutcome::Raised { from, to, .. } => {
            assert_eq!(from, soft_before, "from 必须是抬之前的实际 soft");
            assert!(to > from, "Raised 必须是真的变大：{from} → {to}");
        }
        gateway::nofile::NoFileOutcome::Unchanged { soft, .. } => {
            assert!(
                soft >= target,
                "报告 Unchanged 就必须已经达到目标：soft={soft} target={target}"
            );
        }
        other => panic!("本机不该出现这种启动结论：{other:?}"),
    }

    // ② 不看日志，直接读进程实际生效的额度（Linux）
    if let Ok(text) = std::fs::read_to_string("/proc/self/limits") {
        let (soft, hard_now) =
            gateway::nofile::parse_proc_limits(&text).expect("/proc/self/limits 里必须有该行");
        assert_eq!(hard_now, hard, "hard 不该被改动");
        assert!(
            soft >= target,
            "/proc 里实际生效的 soft 是 {soft}，低于目标 {target} —— 说明 install 没真正生效"
        );
        if can_reproduce {
            assert_eq!(
                soft, target,
                "复现了 systemd 的 1024 之后，必须正好抬到 min(hard, TARGET)"
            );
        }
    }

    agent.shutdown().await;
    gw.shutdown().await;

    // 收尾：还原进来时的 soft，避免影响同一二进制里的其他用例
    let _ = rlimit::setrlimit(rlimit::Resource::NOFILE, original_soft, hard);
}

/// 规格：**启动失败不许改动进程级状态**。
///
/// `Gateway::start` 的顺序是"先构建 TLS 材料（纯校验，注定失败时在碰任何资源之前就返回），
/// 再 `nofile::install()`"。所以一次失败的启动不该抬 NOFILE。
///
/// 为什么值得一条测试：这条顺序**只能**靠测试钉住——把 `start` 里那两行对调，编译、
/// clippy 与其余用例全都照样通过（`Gateway.nofile` 字段只保证 `install()` 被调用过，
/// 不保证它发生在校验之后）。而副作用是有后果的：`deploy/gateway.service` 是
/// `Restart=on-failure`，配置写错时进程非零退出会被反复重启，每次都去改一遍进程的 fd 额度。
///
/// 断言口径与上一条相同：直接读**进程自己**的限额，不信自家日志或返回值。
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_failed_start_leaves_the_process_nofile_limit_untouched() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let (original_soft, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();
    // 把 soft 压到 1024（复现 systemd 未设 LimitNOFILE 时的默认），这样"有没有被抬过"才是
    // 可观测的。
    //
    // 复扫 F4：这里以前是 `eprintln!("skipped…"); return;` —— 那条路径下这条用例**零断言通过**，
    // 与"真的跑过并通过"在 gate/CI 眼里完全一样（`return` 不是 `#[ignore]`，报告里都算 ok）。
    // 前提不成立时唯一诚实的做法是**响**：这条用例在这里证明不了任何东西，就不该报绿。
    assert!(
        hard >= 1024,
        "本环境 NOFILE hard={hard} < 1024，构造不出\"启动前被压到 1024\"的场景 ⇒ 这条用例在这里\
         等于没跑（复扫 F4）。请换一个 hard ≥ 1024 的环境，别让它静默通过"
    );
    assert!(
        rlimit::setrlimit(rlimit::Resource::NOFILE, 1024, hard).is_ok(),
        "hard={hard} ≥ 1024：把 soft 压到 1024 在任何 unix 上都该被允许；失败说明环境有额外限制\
         ⇒ 这条用例在此处等于没跑（复扫 F4）"
    );
    let soft_before = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap().0;

    // 隧道材料合法、只有 HTTPS 材料是垃圾 → 失败点必然在 TLS 构建阶段，早于 install()
    let (ca, server_cert, server_key, _client_cert, _client_key) = gen_certs();
    let result = Gateway::start(GatewayConfig {
        tunnel: TunnelTls::from_der(vec![ca], vec![server_cert], server_key)
            .expect("gen_certs returns non-empty material"),
        opts: Options {
            https: Some(TlsPem {
                cert: b"not a pem".to_vec(),
                key: b"not a key".to_vec(),
            }),
            ..Options::default()
        },
    })
    .await;

    let soft_after = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap().0;
    let _ = rlimit::setrlimit(rlimit::Resource::NOFILE, original_soft, hard);

    assert!(result.is_err(), "垃圾 HTTPS 材料必须让启动失败");
    assert_eq!(
        soft_after, soft_before,
        "启动失败不该改动进程的 NOFILE —— 这正是把纯校验排在副作用之前的目的"
    );
}
