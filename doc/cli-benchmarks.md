# Keyway CLI run overhead

The Phase 2 budget is Keyway-only warm-store overhead: p50 ≤ 50 ms and p95 ≤
100 ms for manifests with one and ten references. Measurements invoke the same
`/usr/bin/true` child directly and through an AOT-compiled CLI harness, then
subtract the direct child median. They use a real login Keychain or Secret
Service store; mocked timings are not accepted.

Reproduce on a disposable release test account:

```sh
KEYWAY_BENCHMARK=1 ./tool/benchmark_cli.sh
```

## Recorded results

### macOS arm64 — 2026-07-13

- Hardware: MacBook Pro 16-inch (2021), Apple M1 Pro, 10 cores, 16 GB
- OS: macOS 26.2 (25C56)
- Build: Dart AOT arm64, 100 warm-store iterations, real login Keychain

| References | Direct-child p50 | Compiled run p50 | Compiled run p95 | Keyway overhead p50 | Keyway overhead p95 |
|---:|---:|---:|---:|---:|---:|
| 1 | 2.329 ms | 40.237 ms | 62.851 ms | **37.908 ms** | **60.522 ms** |
| 10 | 2.263 ms | 39.094 ms | 51.089 ms | **36.831 ms** | **48.825 ms** |

Both reference counts pass the 50 ms p50 / 100 ms p95 overhead budget.

### Linux x64

Pending the Phase 2 CI run on the designated Ubuntu release runner. Generic CI
timing is diagnostic only and does not enforce the budget.
