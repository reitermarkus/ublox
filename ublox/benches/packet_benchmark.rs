use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;
use ublox::*;

struct CpuProfiler;

impl criterion::profiler::Profiler for CpuProfiler {
    fn start_profiling(&mut self, benchmark_id: &str, benchmark_dir: &Path) {
        cpuprofiler::PROFILER
            .lock()
            .unwrap()
            .start(format!("./{}.profile", benchmark_id).as_bytes())
            .unwrap();
    }

    fn stop_profiling(&mut self, benchmark_id: &str, benchmark_dir: &Path) {
        cpuprofiler::PROFILER.lock().unwrap().stop().unwrap();
    }
}

fn profiled() -> Criterion {
    Criterion::default().with_profiler(CpuProfiler)
}

fn parse_all<T: UnderlyingBuffer>(mut parser: Parser<T>, data: &[u8], chunk_size: usize) -> usize {
    let mut count = 0;
    for chunk in data.chunks(chunk_size) {
        let mut it = parser.consume(&chunk[..]);
        while let Some(next) = it.next() {
            match next {
                Ok(packet) => count += 1,
                Err(err) => panic!("No errors allowed! got: {:?}", err),
            }
        }
    }
    count
}

pub fn criterion_benchmark(c: &mut Criterion) {
    for chunk in &[99, 100, 101, 256, 512, 1000, 1024] {
        c.bench_function(&format!("vec_parse_pos_{}", chunk), |b| {
            b.iter(|| {
                let data = std::include_bytes!("pos.ubx");
                let mut parser = Parser::default();
                assert_eq!(parse_all(parser, data, *chunk), 2801);
            })
        });
    }
    for (buf_size, chunk) in &[(256, 100), (256, 256), (256, 512), (256, 1024)] {
        let mut underlying = vec![0; *buf_size];
        c.bench_function(&format!("array_parse_pos_{}_{}", buf_size, chunk), |b| {
            b.iter(|| {
                let data = std::include_bytes!("pos.ubx");
                let mut underlying = FixedLinearBuffer::new(&mut underlying);
                let mut parser = Parser::new(underlying);
                assert_eq!(parse_all(parser, data, *chunk), 2801);
            })
        });
    }
}

criterion_group! {
name = benches;
config = profiled();
targets = criterion_benchmark
}
criterion_main!(benches);
