# Benchmark Results

Last updated: v0.10.1

## How to Run

```bash
# Micro-benchmarks (criterion, in-memory MockRepository)
cargo bench

# HTTP load tests (requires running Docker Compose stack + hey)
./scripts/load-test.sh          # default suite
./scripts/load-test.sh quick    # fast smoke test
./scripts/load-test.sh burst    # high concurrency spike
./scripts/load-test.sh sustained # 60s sustained ingestion

# Chaos/resilience tests
./scripts/chaos-test.sh
```

---

## HTTP Load Tests (Docker Compose)

End-to-end through nginx -> prefixd -> PostgreSQL on a single machine.

| Endpoint | Req/sec | Avg Latency | P99 Latency |
|----------|---------|-------------|-------------|
| `GET /v1/health` | ~8,000 | 1.3 ms | 2.6 ms |
| `GET /v1/mitigations` | ~4,800 | 2.1 ms | 3.1 ms |
| `POST /v1/events` (ingestion) | ~4,700 | 1.1 ms | 1.6 ms |
| `GET /metrics` (under load) | ~680 | 2.9 ms | 7.0 ms |

**Burst test:** 500 requests at 50 concurrency — ~4,930 req/s, zero 5xx errors.

**Sustained test:** 60s at 10 concurrency — throughput stable, API healthy after completion, DB pool not exhausted.

### Context

A typical DDoS detector (FastNetMon, Kentik) generates 10-50 events/sec during an attack. At ~4,700 events/sec, prefixd has **~100x headroom** over realistic production load.

---

## Micro-Benchmarks (Criterion)

All times are median values from criterion runs with MockRepository (in-memory). These measure pure computation without network or PostgreSQL overhead.

### Summary

| Operation | Time | Throughput |
|-----------|------|------------|
| Inventory IP lookup (hit) | 156 ns | ~6.4M ops/sec |
| Inventory IP lookup (miss) | 1.22 µs | ~820K ops/sec |
| Inventory is_owned (hit) | 775 ns | ~1.3M ops/sec |
| Inventory is_owned (miss) | 1.22 µs | ~820K ops/sec |
| Scope hash (SHA256) | 119 ns | ~8.4M ops/sec |
| Mock DB insert mitigation | 1.36 µs | ~735K ops/sec |
| Mock DB get mitigation | 144 ns | ~6.9M ops/sec |
| Mock DB list mitigations (100 rows) | 10.1 µs | ~99K ops/sec |
| Mock DB count active | 27 ns | ~37M ops/sec |
| Mock DB safelist check | 136 ns | ~7.4M ops/sec |
| JSON serialize mitigation | 880 ns | ~1.1M ops/sec |
| JSON deserialize mitigation | 1.03 µs | ~970K ops/sec |
| MatchCriteria clone | 20 ns | ~51M ops/sec |
| Scope hash (4 ports) | 119 ns | ~8.4M ops/sec |
| Scope hash (2 ports) | 117 ns | ~8.5M ops/sec |
| UUID v4 generate | 445 ns | ~2.2M ops/sec |
| UUID to string | 22 ns | ~45M ops/sec |

### Inventory Lookups

```
inventory_lookup_hit     156 ns     IP found in inventory
inventory_lookup_miss    1.22 µs    IP not in inventory (full scan)
inventory_is_owned_hit   775 ns     Check if IP is in any customer prefix
inventory_is_owned_miss  1.22 µs    Not owned (full scan)
```

Lookup hits are fast (~156ns). Misses are ~8x slower because they must scan all prefixes before returning. For deployments with 500+ customers, a prefix trie could improve miss performance.

### Inventory Scaling

| Customers | Lookup Time | Notes |
|-----------|-------------|-------|
| 10 | 133 ns | Baseline |
| 50 | 647 ns | 4.9x |
| 100 | 771 ns | 5.8x |
| 500 | 771 ns | 5.8x (plateaus) |

Lookup time plateaus around 100 customers due to prefix-based matching convergence.

### Database Operations (MockRepository)

```
db_insert_mitigation     1.36 µs    Insert new mitigation
db_get_mitigation        144 ns     Fetch by UUID
db_list_mitigations      10.1 µs    List with filters (100 rows, LIMIT 50)
db_count_active          27 ns      Count active mitigations
db_is_safelisted         136 ns     Check safelist with prefix matching
```

### Database List Scaling

| Rows | Time | Notes |
|------|------|-------|
| 10 | 2.09 µs | Baseline |
| 50 | 10.1 µs | 4.8x |
| 100 | 9.90 µs | 4.7x |
| 500 | 9.92 µs | 4.7x (LIMIT 50 caps work) |

The LIMIT 50 clause keeps result set processing constant once the table exceeds the page size.

### Serialization

```
mitigation_serialize_json      880 ns     Mitigation -> JSON
mitigation_deserialize_json    1.03 µs    JSON -> Mitigation
match_criteria_clone           20 ns      Clone MatchCriteria
scope_hash_4_ports             119 ns     SHA256 scope hash (4 ports)
scope_hash_2_ports             117 ns     SHA256 scope hash (2 ports)
uuid_v4_generate               445 ns     Generate random UUID v4
uuid_to_string                 22 ns      Format UUID as string
```

---

## Bottleneck Analysis

For a typical event ingestion flow:

```
Event received          →  ~0 ns    (network I/O, not measured)
JSON deserialization    →  ~1 µs
Inventory lookup        →  ~156 ns
Policy evaluation       →  ~500 ns  (estimated)
Guardrails + safelist   →  ~200 ns
Scope hash              →  ~119 ns
DB insert (PostgreSQL)  →  ~200 µs  (real DB, network + fsync)
BGP announcement        →  ~1-10 ms (GoBGP gRPC)
───────────────────────────────────
Total                   →  ~1-10 ms (dominated by BGP gRPC)
```

The BGP announcement is the slowest step by design — FlowSpec rules must propagate to routers. All prefixd processing overhead (<5µs) is negligible compared to the DB write (~200µs) and BGP announcement (~1-10ms).

---

## Chaos Test Results

17/17 tests passing (see `scripts/chaos-test.sh`):

| Scenario | Result |
|----------|--------|
| Postgres kill during ingestion | API returns 500 gracefully, no crash |
| Postgres restart recovery | Full recovery, ingestion resumes |
| Postgres restart preserves state | Mitigation count unchanged |
| GoBGP kill during mitigations | Ingestion continues (DB-only) |
| GoBGP restart reconciliation | Rules re-announced within 30s |
| prefixd restart | State preserved from PostgreSQL |
| 3x rapid restart | Healthy after all restarts |
| SIGKILL recovery | Clean startup, ingestion works |
| nginx outage | API unreachable (expected), recovers on restart |

---

## Performance Recommendations

### Current State: Production Ready

The current performance supports:
- **Event ingestion:** ~4,700 events/sec end-to-end (100x typical load)
- **API queries:** Sub-3ms P99 for read operations
- **Burst handling:** 50 concurrent connections, zero errors
- **Recovery:** Sub-30s full recovery from any component failure

### Future Optimizations (if needed)

1. **Prefix trie for inventory** — improve miss lookups from O(n) to O(log n)
2. **Batch audit log writes** — accumulate and flush periodically
3. **PostgreSQL tuning** — shared_buffers, work_mem, WAL settings (defaults used currently)
4. **PgBouncer** — connection pooling for higher sustained write throughput
5. **Read replicas** — separate dashboard queries from ingestion path
