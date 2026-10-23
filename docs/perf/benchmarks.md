# Historical benchmark report

This preserves the numbers reported for v0.15.0. The original measurement date,
hardware, exact workloads and dated raw receipts are not recorded here. These
values have not been remeasured for the current controller or rustbgpd adapter.
The old load helper could count HTTP errors as throughput and discarded its
background ingestion output, so its numbers cannot qualify successful ingestion
or current capacity. The microbenchmarks and recovery reports have the separate
limits described below.

## How to Run

```bash
# Micro-benchmarks (Criterion, in-memory MockRepository)
cargo bench
```

The HTTP load harness and its report-parser tests have been retired. The HTTP
request-rate results below remain unqualified historical evidence; they do not
establish admitted mitigation capacity, speaker acceptance, export or router
enforcement.

---

## HTTP load tests (historical Compose report)

The original report described nginx -> prefixd -> PostgreSQL on one machine.
The table is an unqualified historical HTTP request-rate report, not an admitted
mitigation rate or a current deployment limit.

| Endpoint | Req/sec | Avg Latency | P99 Latency |
|----------|---------|-------------|-------------|
| `GET /v1/health` | ~8,000 | 1.3 ms | 2.6 ms |
| `GET /v1/mitigations` | ~4,800 | 2.1 ms | 3.1 ms |
| `POST /v1/events` (ingestion) | ~4,700 | 1.1 ms | 1.6 ms |
| `GET /metrics` (under load) | ~680 | 2.9 ms | 7.0 ms |

**Reported burst:** 500 requests at 50 concurrency — ~4,930 req/s, zero 5xx
errors. The old check did not reject 4xx or transport errors.

**Reported sustained run:** 60s at 10 concurrency, described as stable throughput
with a healthy API and an available DB pool afterward. Its request-status and
pool probes, with no linked raw run evidence, do not qualify current capacity
or recovery.

### Context

The previous comparison assumed detector traffic of 10–50 events/sec. That
assumption and the unqualified request rate do not establish production
headroom. Customer inventory, admitted actions, database state, audit writes and
speaker behavior need a dated workload-specific measurement.

---

## Micro-Benchmarks (Criterion)

These were reported as median Criterion values with MockRepository (in-memory).
They exclude network and PostgreSQL I/O and do not qualify the current code.
The original inputs and raw run history are not available on this page.

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

The historical hit/miss figures differ by roughly 8x. Without the original
inventory and run receipts, they do not establish current scaling or justify a
particular replacement data structure.

### Inventory Scaling

| Customers | Lookup Time | Notes |
|-----------|-------------|-------|
| 10 | 133 ns | Baseline |
| 50 | 647 ns | 4.9x |
| 100 | 771 ns | 5.8x |
| 500 | 771 ns | 5.8x (plateaus) |

The reported plateau is limited to these cases; it does not demonstrate general
inventory scaling without their original inputs.

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

These MockRepository cases used LIMIT 50. Their plateau is not evidence of
PostgreSQL list/query scaling.

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

## Former latency illustration (unqualified)

The earlier report mixes component microbenchmarks, an explicit policy estimate
and unqualified PostgreSQL/RPC figures. No dated end-to-end trace is linked
here; these figures cannot qualify the total:

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

The former <5µs controller-overhead comparison has no linked trace qualifying
that total. A successful GoBGP RPC, retained local intent, export and router
enforcement are separate observations. The unqualified ~1–10ms RPC figure above
says nothing about propagation or enforcement latency and provides no rustbgpd
measurement.

---

## Historical recovery report

The original report listed 17/17 passing checks with `scripts/chaos-test.sh`.
The table preserves those reported outcomes, without dated raw receipts or
failed attempts that could qualify them. The helper uses fixed container names
and assumes GoBGP. It is not qualified for the current selected profiles and
was not run for this documentation correction.

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

## What new qualification needs

Use an owned isolated fixture, record the date, exact revisions, backend,
hardware, configuration, dataset, load shape and raw output for every attempt.
Define HTTP success separately from admitted mitigation counts, successful
speaker RPCs, export and router enforcement. Keep rejected requests and failed
runs visible rather than presenting a later successful run as the whole history.

Recovery evidence must name the component, fault, sequence and observation
boundary that were tested. The historical cases above do not establish a
recovery bound for arbitrary failures or current production readiness. No new
capacity or recovery measurement was performed for this correction.
