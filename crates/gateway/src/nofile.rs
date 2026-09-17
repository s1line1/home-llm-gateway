//! 启动时把 `RLIMIT_NOFILE` 的软上限抬到一个**明确的目标值**（默认 16384，见
//! [`TARGET_SOFT_LIMIT`]），而不是"顶到 hard"。
//!
//! 背景（2026-09-17 云端实测）：`gateway.service` 没有设置 `LimitNOFILE`，于是进程吃的是
//! systemd 的全局默认 —— `/proc/<pid>/limits` 显示 `Max open files 1024 524288`。
//! **1024 不是内核限制**（`fs.nr_open` 是 1048576，同机 `cron` 也是 1024，`sshd` 则自己抬到了
//! 1048576），而是"没人设就用 1024"的默认软上限。
//!
//! 撞上它的症状是**新连接被拒而进程完全健康**：
//!
//! - 网关日志：`accept error: Too many open files (os error 24)`（实测 296 次，与压测窗口吻合）；
//! - 客户端看到的是 `connection reset by peer`，很容易被误判成网络问题；
//! - 连带的二级症状：`accept` 卡住 → 内核 accept 队列（mio 写死的 128）被填满 →
//!   dmesg 冒出 `Possible SYN flooding on port 9090. Sending cookies.`。
//!
//! 实测水位：768 个并发客户端连接时网关 fd 峰值 **785**（≈ 每连接 1 fd，加上 QUIC 的单个 UDP
//! socket、SQLite、日志文件等十余个），也就是说默认的 1024 在生产水位上是贴脸的。
//!
//! 为什么可以在代码里改：Unix 的 `RLIMIT_NOFILE` 有两个值——soft（运行时**实际强制执行**的
//! 额度，fd 用满即 `EMFILE`）与 hard（soft 允许抬到的**天花板**）。**任何进程都能把自己的
//! soft 抬到 hard 以内**，不需要特权、不改内核、也不影响其他进程。这里做的就是这一件事。
//!
//! **为什么不直接抬到 hard（524288）**：上限给到几十万，等于把"fd 泄漏"的引爆点从本进程
//! 的 `EMFILE`（止损范围只有一个进程，日志里直接可见）推迟到整机的 `fs.file-max`/内存
//! （拖垮同机其他服务，且现场更难还原）。16384 已经远高于任何合理水位（约 20 倍余量），
//! 真泄漏时在本进程内就能撞上、能被发现，代价也不外溢。
//!
//! 与"在 unit 里写 `LimitNOFILE`"的关系：两者不冲突，分工是——unit 决定 **hard**（真正的
//! 天花板），这里把 soft 抬到 `min(hard, TARGET)`。好处是**换机器、重写 unit、运维忘了配**
//! 都不会再撞 systemd 那个 1024；代价是它对 unit 配置不可见（只能从启动日志与
//! `/proc/<pid>/limits` 看出来），所以成功时也必须留一行 INFO 日志。
//!
//! 失败**只告警、不致命**：抬额度是尽力而为的优化。容器里 hard 被压到 1024、或平台不支持时，
//! 网关照样要能启动——把"优化失败"升级成"启动失败"会让可用性更差。

/// 目标软上限：**够用 + 足量余量**，不是越大越好。
///
/// 取值依据（云端实测 2026-09-17）：768 个并发客户端连接 → 网关 fd 峰值 785；
/// 上限压测档位到 1536 并发也要 ≈1600 个 fd。16384 约为实测水位的 **20 倍**，
/// 足够覆盖"并发连接数 × (1 fd/连接 + 少量固定开销)"，同时避免把 fd 泄漏的引爆点
/// 推到整机（见模块注释）。
///
/// 想改数值就改这一个常量；若某环境 hard 比它还小，则自动退化为 `hard`。
pub const TARGET_SOFT_LIMIT: u64 = 16_384;

/// 一次尝试的结果。做成枚举（而不是"看日志里有没有那一行"）是为了让调用方和测试
/// 都能区分三种情况。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoFileOutcome {
    /// 没有变化：soft 已经达到 `min(hard, TARGET_SOFT_LIMIT)`。
    ///
    /// 到顶**不一定等于 soft == hard**：hard 可能更大（我们**故意**不去顶满），
    /// 也可能被平台压住（macOS 的 `kern.maxfilesperproc`，实测 hard = i64::MAX
    /// 而 soft 上限 1048575）。
    Unchanged { soft: u64, hard: u64 },
    /// 抬上去了：`from` → `to`（`to = min(hard, TARGET_SOFT_LIMIT)`，含平台实际接受值）。
    Raised { from: u64, to: u64, hard: u64 },
    /// 该平台没有 `RLIMIT_NOFILE`（Windows）。
    Unsupported,
}

/// 把 soft 抬到 `min(hard, TARGET_SOFT_LIMIT)`（尽力而为，返回值描述实际发生了什么）。
///
/// 函数名刻意不叫 `raise_soft_to_hard`：目标**不是** hard，而是 [`TARGET_SOFT_LIMIT`]；
/// hard 只是不可逾越的天花板。
///
/// 三条不变量：
/// 1. **只抬不降**——soft 绝不因为这次调用而变小；
/// 2. **不动 hard**——hard 是别人（systemd/容器）给的天花板，改它属于越权；
/// 3. **如实上报**——返回值里是内核实际接受的 soft，而不是期望值。
///
/// ⚠️ 不要改用 `rlimit::increase_nofile_limit`：它在 macOS 上会把 soft 设成
/// `min(lim, hard, kern.maxfilesperproc)`，而 `kern.maxfilesperproc` 可能**低于**当前 soft
/// （实测本机：soft 已是 1048575，该函数把它压回 61440）——那是"把额度改小"，直接违反第 1 条。
#[cfg(unix)]
pub fn raise_to_target() -> std::io::Result<NoFileOutcome> {
    let (soft, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE)?;
    // hard 可能小于目标（容器/unit 收紧过），此时能到的最大就是 hard。
    let target = hard.min(TARGET_SOFT_LIMIT);
    if soft >= target {
        return Ok(NoFileOutcome::Unchanged { soft, hard });
    }
    // 只设 soft，hard 原样传回。
    rlimit::setrlimit(rlimit::Resource::NOFILE, target, hard)?;
    // 以内核实际生效值为准（某些平台会自行夹取），避免"日志说 16384、实际是别的值"。
    let (now, _) = rlimit::getrlimit(rlimit::Resource::NOFILE)?;
    if now > soft {
        Ok(NoFileOutcome::Raised {
            from: soft,
            to: now,
            hard,
        })
    } else {
        Ok(NoFileOutcome::Unchanged { soft, hard })
    }
}

#[cfg(not(unix))]
pub fn raise_to_target() -> std::io::Result<NoFileOutcome> {
    Ok(NoFileOutcome::Unsupported)
}

/// 启动时调用一次：抬额度并把结果写进日志。
///
/// 失败只告警——见模块注释"失败只告警、不致命"。告警文案要带上**可执行的下一步**
/// （改 unit 的 `LimitNOFILE`），否则运维看到 "could not raise" 也不知道该做什么。
pub fn install() {
    match raise_to_target() {
        Ok(NoFileOutcome::Raised { from, to, hard }) => {
            // limited_by_hard=true 表示"环境的天花板比目标值还低"（unit/容器收紧过），
            // 那才真的到不了目标值；否则是**我们主动停**在 TARGET_SOFT_LIMIT。
            // 两者必须能区分，否则运维会把"设计如此"读成"被系统压住了"。
            tracing::info!(
                from,
                to,
                hard,
                target = TARGET_SOFT_LIMIT,
                limited_by_hard = to == hard,
                "raised NOFILE soft limit"
            )
        }
        Ok(NoFileOutcome::Unchanged { soft, hard }) => {
            tracing::debug!(
                soft,
                hard,
                target = TARGET_SOFT_LIMIT,
                "NOFILE soft limit already at or above the target"
            )
        }
        Ok(NoFileOutcome::Unsupported) => {
            tracing::debug!("RLIMIT_NOFILE is not adjustable on this platform")
        }
        Err(e) => tracing::warn!(
            error = %e,
            "could not raise the NOFILE soft limit; if you see 'Too many open files', \
             set LimitNOFILE in the service unit (it sets the ceiling this code can raise to)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格：**systemd 给的 1024 必须被抬到目标值**，且只抬不降、重复调用幂等。
    ///
    /// 测试自己先把 soft 降到 1024（复现云端那个默认值），否则本机继承来的 soft 可能已经
    /// 高于目标值、"抬"这条路径根本不会被走到——那就成了"测个不报错"。
    ///
    /// 断言刻意**不写成 soft == hard**：目标是 `min(hard, TARGET_SOFT_LIMIT)`，
    /// 云端 hard=524288 时应当停在 16384（远小于 hard），这是设计意图而不是失败。
    ///
    /// 用一个测试覆盖全部断言（而不是拆成多个 `#[test]`）：`RLIMIT_NOFILE` 是**进程级全局
    /// 状态**，并行跑的多个用例会互相踩。
    #[test]
    fn raises_soft_from_the_systemd_default_to_the_target_and_is_idempotent() {
        #[cfg(unix)]
        {
            let (original_soft, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();
            let expected_target = hard.min(TARGET_SOFT_LIMIT);

            // 模拟 systemd 的默认（soft=1024，hard 不动）；环境若不允许就当跳过这一档，
            // 但仍要走过"幂等 + 不变量"的断言。
            let lowered = rlimit::setrlimit(rlimit::Resource::NOFILE, 1024.min(hard), hard).is_ok();
            let soft_before = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap().0;
            assert!(soft_before <= hard);

            let first = raise_to_target().expect("读/写 RLIMIT_NOFILE 不该失败");
            let (soft_after, hard_after) = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();

            assert_eq!(
                hard_after, hard,
                "hard 不该被改动（那是 systemd/容器 的地盘）"
            );
            assert!(
                soft_after >= soft_before,
                "抬额度绝不能把 soft 变小：{soft_before} → {soft_after}"
            );

            match first {
                NoFileOutcome::Raised { from, to, hard: h } => {
                    assert_eq!(from, soft_before, "from 必须是抬之前的 soft");
                    assert_eq!(to, soft_after, "to 必须等于实际生效的 soft（不能只报意图）");
                    assert_eq!(h, hard);
                    assert!(
                        to <= TARGET_SOFT_LIMIT.max(hard.min(TARGET_SOFT_LIMIT)),
                        "不该超过目标值：to={to} target={expected_target}"
                    );
                    if lowered && expected_target > 1024 {
                        assert_eq!(to, expected_target, "应当正好抬到 min(hard, TARGET)");
                    }
                }
                NoFileOutcome::Unchanged { soft, hard: h } => {
                    // 已经达到目标（或环境压根没让我们降下来）
                    assert_eq!(soft, soft_after);
                    assert_eq!(h, hard);
                    assert!(
                        soft >= expected_target,
                        "报 Unchanged 就必须已经达到目标：soft={soft} target={expected_target}"
                    );
                }
                NoFileOutcome::Unsupported => panic!("unix 上不该是 Unsupported"),
            }

            // 幂等：第二次必然无事可做，且不改变任何值
            let second = raise_to_target().unwrap();
            let (soft_final, hard_final) = rlimit::getrlimit(rlimit::Resource::NOFILE).unwrap();
            assert_eq!(soft_final, soft_after, "重复调用不该改变 soft");
            assert_eq!(hard_final, hard, "重复调用不该改变 hard");
            match second {
                NoFileOutcome::Unchanged { soft, .. } => assert_eq!(soft, soft_final),
                other => panic!("重复调用应当无事可做，实际：{other:?}"),
            }

            // 收尾：把 soft 还原成进来时的值（同一个测试进程里还有别的用例）
            let _ = rlimit::setrlimit(rlimit::Resource::NOFILE, original_soft, hard);
        }

        #[cfg(not(unix))]
        assert_eq!(raise_to_target().unwrap(), NoFileOutcome::Unsupported);
    }
}
