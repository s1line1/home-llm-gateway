//! 隧道帧编解码基准（Criterion）：序列化/反序列化 + 帧读写吞吐。
//! 运行：cargo bench -p proto

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use proto::io::{read_frame, write_frame};
use proto::Frame;

fn frame_fixtures() -> Vec<Frame> {
    vec![
        // 小控制帧
        Frame::Register {
            agent_id: "home-1".into(),
            models: vec!["qwen2.5".into(), "llama3".into()],
            max_concurrency: 4,
            version: "0.1.0".into(),
        },
        Frame::Heartbeat {
            agent_id: "home-1".into(),
            inflight: 3,
        },
        // 典型代理请求（1KiB body）
        Frame::ProxyRequest {
            request_id: 42,
            method: "POST".into(),
            path: "/v1/chat/completions?stream=true".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                (
                    "authorization".into(),
                    "Bearer sk-0123456789abcdef0123456789abcdef".into(),
                ),
            ],
            body: vec![b'a'; 1024],
        },
        // SSE 流块（4KiB）
        Frame::ProxyResponseBody {
            request_id: 42,
            chunk: vec![b'd'; 4096],
        },
        // 最大常见块（64KiB）
        Frame::ProxyResponseBody {
            request_id: 7,
            chunk: vec![b'x'; 64 * 1024],
        },
    ]
}

fn bench_roundtrip(c: &mut Criterion) {
    let fixtures = frame_fixtures();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("frame/roundtrip");
    for frame in &fixtures {
        let name = match frame {
            Frame::Register { .. } => "register",
            Frame::Heartbeat { .. } => "heartbeat",
            Frame::ProxyRequest { .. } => "proxy-request-1k",
            Frame::ProxyResponseBody { chunk, .. } if chunk.len() == 4096 => "sse-chunk-4k",
            _ => "sse-chunk-64k",
        };
        let mut buf = Vec::new();
        rt.block_on(write_frame(&mut buf, frame)).unwrap();
        group.throughput(Throughput::Bytes(buf.len() as u64));
        group.bench_with_input(BenchmarkId::new(name, buf.len()), frame, |b, f| {
            b.iter_batched(
                || f.clone(),
                |f| {
                    let mut buf = Vec::with_capacity(1024);
                    rt.block_on(async {
                        write_frame(&mut buf, &f).await.unwrap();
                        let mut reader = buf.as_slice();
                        black_box(read_frame(&mut reader).await.unwrap())
                    });
                    black_box(buf.len())
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// 仅序列化（写帧），纯 CPU 成本，无 tokio runtime 开销。
fn bench_serialize(c: &mut Criterion) {
    let fixtures = frame_fixtures();
    let mut group = c.benchmark_group("frame/serialize");
    for frame in &fixtures {
        let size = postcard::to_allocvec(frame).unwrap().len();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("serialize", size), frame, |b, f| {
            b.iter(|| black_box(postcard::to_allocvec(f).unwrap().len()))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_roundtrip, bench_serialize);
criterion_main!(benches);
