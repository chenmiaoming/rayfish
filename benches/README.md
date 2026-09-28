# Data-path microbenchmarks

Criterion benchmarks that time the CPU/allocation work rayfish does **per
forwarded packet**, in isolation from the network. They complement the cloud
end-to-end harness (`tests/bench/`): on a shared-vCPU box single-stream TCP is
loss/congestion-bound, which hides per-packet CPU savings, so these hold
everything else constant and measure only the data plane.

```bash
cargo bench                       # all benches
cargo bench --bench forward       # just this one
cargo bench --bench forward -- handoff   # filter by group/id
cargo bench --bench apple_bridge # CSV report for bridge comparisons
```

Criterion writes HTML reports + regression baselines under `target/criterion/`;
a second run prints `change: [...]` deltas vs the stored baseline.

## Groups (`benches/forward.rs`)

- **`handoff`** compares the old allocation-and-copy packet handoff with the
  current `Bytes` paths for TX and RX.
- **`tun_ingress`** compares the old scratch-buffer copy plus pool copy with
  extending the owned packet buffer directly.
- **`apple_tun_ingress`** compares the former per-packet Swift bridge queue,
  allocation and pool copy with direct ingress, plus a candidate batch queue
  at batch sizes 1, 8 and 32.
- **`apple_bridge`** prints CSV rows for per-packet bridge, batched bridge, and
  owned-packet handoff cases. It reports packet and byte throughput, p50/p99
  per-packet latency, process CPU use, measured allocations, modeled copies,
  queue high-water mark, and drops.
- **`writer_resolve`** compares resolving the swappable TUN sender on each
  packet with the reader's cached lookup.
- **`firewall`** measures packet parsing and evaluation for the default allow
  path and a small inbound whitelist.

Ingress cases use 64, 256, 1200 and 1500 byte packets. They measure buffer
copies, allocation and queue overhead in memory. They do not call an OS TUN or
utun device, so they estimate the per-packet CPU saved in those paths, not
end-to-end packet latency. The old bridge and candidate batch variants are
fixtures, not live code paths. These results do not include NetworkExtension
callback lookup, real queue contention and backpressure, or tunnel latency.
The batch harness drains synchronously, so it reports a queue high-water mark
of one and no drops by construction. Run release benchmarks on Apple Silicon
before drawing conclusions about the macOS packet path.
