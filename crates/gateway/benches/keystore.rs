//! API Key 存储基准（Criterion）：argon2 哈希/校验、authorize 命中与未命中。
//! 运行：cargo bench -p gateway --bench keystore
//! 注意：argon2 默认参数（m=19456/t=2）单次约 10-30ms，基准耗时较长属预期。

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use gateway::keystore::KeyStore;

fn bench_keystore(c: &mut Criterion) {
    let store = KeyStore::new(None);
    let created = store.create("bench".into());
    let plaintext = created.plaintext.clone();
    let _id = created.record.id;

    // 创建 key（哈希 + 落内存索引）：每次新建 store 保持独立测量
    c.bench_function("keystore/create-key", |b| {
        b.iter_batched(
            || KeyStore::new(None),
            |s| black_box(s.create("bench".into())),
            criterion::BatchSize::SmallInput,
        )
    });

    // authorize 命中（sha256 lookup + argon2 verify）
    c.bench_function("keystore/authorize-hit", |b| {
        b.iter(|| black_box(store.authorize(&plaintext)))
    });

    // authorize 未命中（lookup 不在表，零 argon2 成本——验证 O(1) 快速拒绝）
    c.bench_function("keystore/authorize-miss", |b| {
        b.iter(|| black_box(store.authorize("sk-not-a-real-key-00000000000000000000000000")))
    });
}

criterion_group!(benches, bench_keystore);
criterion_main!(benches);
