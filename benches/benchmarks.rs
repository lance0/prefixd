use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use prefixd::config::{AllowedPorts, Asset, Customer, Inventory, Service};
use prefixd::db::{MockRepository, RepositoryTrait};
use prefixd::domain::{
    ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationStatus,
};

fn test_inventory() -> Inventory {
    let mut customers = Vec::new();
    for i in 0..100 {
        customers.push(Customer {
            customer_id: format!("cust_{}", i),
            name: format!("Customer {}", i),
            prefixes: vec![format!("203.0.{}.0/24", i)],
            policy_profile: prefixd::config::PolicyProfile::Normal,
            services: vec![Service {
                service_id: format!("svc_{}", i),
                name: "DNS".to_string(),
                assets: (0..10)
                    .map(|j| Asset {
                        ip: format!("203.0.{}.{}", i, j + 10),
                        role: Some("server".to_string()),
                    })
                    .collect(),
                allowed_ports: AllowedPorts {
                    udp: vec![53],
                    tcp: vec![53, 80, 443],
                },
            }],
        });
    }
    Inventory::new(customers)
}

fn make_mitigation(i: usize) -> Mitigation {
    let event_id = uuid::Uuid::new_v4();
    Mitigation {
        mitigation_id: uuid::Uuid::new_v4(),
        scope_hash: format!("hash_{}", i),
        pop: "bench1".to_string(),
        customer_id: Some(format!("cust_{}", i % 100)),
        service_id: Some(format!("svc_{}", i % 100)),
        victim_ip: format!("203.0.{}.{}", i / 256, i % 256),
        vector: AttackVector::UdpFlood,
        match_criteria: MatchCriteria {
            dst_prefix: format!("203.0.{}.{}/32", i / 256, i % 256),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        action_type: ActionType::Discard,
        action_params: ActionParams { rate_bps: None },
        status: MitigationStatus::Active,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        withdrawn_at: None,
        triggering_event_id: event_id,
        last_event_id: event_id,
        escalated_from_id: None,
        reason: "benchmark test".to_string(),
        rejection_reason: None,
    }
}

// Benchmark: Inventory lookup
fn bench_inventory_lookup(c: &mut Criterion) {
    let inventory = test_inventory();

    c.bench_function("inventory_lookup_hit", |b| {
        b.iter(|| black_box(inventory.lookup_ip("203.0.50.15")))
    });

    c.bench_function("inventory_lookup_miss", |b| {
        b.iter(|| black_box(inventory.lookup_ip("8.8.8.8")))
    });

    c.bench_function("inventory_is_owned_hit", |b| {
        b.iter(|| black_box(inventory.is_owned("203.0.50.100")))
    });

    c.bench_function("inventory_is_owned_miss", |b| {
        b.iter(|| black_box(inventory.is_owned("8.8.8.8")))
    });
}

// Benchmark: Scope hash computation
fn bench_scope_hash(c: &mut Criterion) {
    let criteria = MatchCriteria {
        dst_prefix: "203.0.1.10/32".to_string(),
        protocol: Some(17),
        dst_ports: vec![53, 80, 443],
    };

    c.bench_function("scope_hash_compute", |b| {
        b.iter(|| black_box(criteria.compute_scope_hash()))
    });
}

// Benchmark: Database operations using MockRepository
fn bench_database_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("db_insert_mitigation", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let repo = MockRepository::new();

            let start = std::time::Instant::now();
            for i in 0..iters {
                let m = make_mitigation(i as usize);
                let _ = repo.insert_mitigation(&m).await;
            }
            start.elapsed()
        })
    });

    c.bench_function("db_get_mitigation", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let repo = MockRepository::new();

            let mut ids = Vec::new();
            for i in 0..100 {
                let m = make_mitigation(i);
                repo.insert_mitigation(&m).await.unwrap();
                ids.push(m.mitigation_id);
            }

            let start = std::time::Instant::now();
            for i in 0..iters {
                let id = ids[i as usize % ids.len()];
                let _ = repo.get_mitigation(id).await;
            }
            start.elapsed()
        })
    });

    c.bench_function("db_list_mitigations", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let repo = MockRepository::new();

            for i in 0..100 {
                let m = make_mitigation(i);
                repo.insert_mitigation(&m).await.unwrap();
            }

            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = repo.list_mitigations(None, None, None, 50, 0).await;
            }
            start.elapsed()
        })
    });

    c.bench_function("db_count_active", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let repo = MockRepository::new();

            for i in 0..100 {
                let m = make_mitigation(i);
                repo.insert_mitigation(&m).await.unwrap();
            }

            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = repo.count_active_global().await;
            }
            start.elapsed()
        })
    });

    c.bench_function("db_is_safelisted", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let repo = MockRepository::new();

            for i in 0..10 {
                repo.insert_safelist(&format!("10.0.{}.0/24", i), "bench", None)
                    .await
                    .unwrap();
            }

            let start = std::time::Instant::now();
            for i in 0..iters {
                let ip = format!("10.0.{}.1", i % 20);
                let _ = repo.is_safelisted(&ip).await;
            }
            start.elapsed()
        })
    });
}

// Benchmark: Mitigation serialization
fn bench_serialization(c: &mut Criterion) {
    let mitigation = make_mitigation(0);

    c.bench_function("mitigation_serialize_json", |b| {
        b.iter(|| black_box(serde_json::to_string(&mitigation)))
    });

    let json = serde_json::to_string(&mitigation).unwrap();
    c.bench_function("mitigation_deserialize_json", |b| {
        b.iter(|| black_box(serde_json::from_str::<Mitigation>(&json)))
    });
}

// Benchmark: MatchCriteria operations
fn bench_match_criteria(c: &mut Criterion) {
    let criteria1 = MatchCriteria {
        dst_prefix: "203.0.1.10/32".to_string(),
        protocol: Some(17),
        dst_ports: vec![53, 80, 443, 8080],
    };

    let criteria2 = MatchCriteria {
        dst_prefix: "203.0.1.10/32".to_string(),
        protocol: Some(17),
        dst_ports: vec![53, 443],
    };

    c.bench_function("match_criteria_clone", |b| {
        b.iter(|| black_box(criteria1.clone()))
    });

    c.bench_function("match_criteria_hash_4_ports", |b| {
        b.iter(|| black_box(criteria1.compute_scope_hash()))
    });

    c.bench_function("match_criteria_hash_2_ports", |b| {
        b.iter(|| black_box(criteria2.compute_scope_hash()))
    });
}

// Benchmark: UUID generation
fn bench_uuid(c: &mut Criterion) {
    c.bench_function("uuid_v4_generate", |b| {
        b.iter(|| black_box(uuid::Uuid::new_v4()))
    });

    let id = uuid::Uuid::new_v4();
    c.bench_function("uuid_to_string", |b| b.iter(|| black_box(id.to_string())));
}

// Group benchmarks with different sample sizes for DB operations
fn bench_db_scaling(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("db_list_scaling");

    for size in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("list_mitigations", size),
            size,
            |b, &size| {
                b.to_async(&rt).iter_custom(|iters| async move {
                    let repo = MockRepository::new();

                    for i in 0..size {
                        let m = make_mitigation(i);
                        repo.insert_mitigation(&m).await.unwrap();
                    }

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let _ = repo.list_mitigations(None, None, None, 50, 0).await;
                    }
                    start.elapsed()
                })
            },
        );
    }
    group.finish();
}

// Benchmark: Inventory scaling
fn bench_inventory_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("inventory_scaling");

    for num_customers in [10, 50, 100, 500].iter() {
        let mut customers = Vec::new();
        for i in 0..*num_customers {
            customers.push(Customer {
                customer_id: format!("cust_{}", i),
                name: format!("Customer {}", i),
                prefixes: vec![format!("203.{}.0.0/16", i % 256)],
                policy_profile: prefixd::config::PolicyProfile::Normal,
                services: vec![],
            });
        }
        let inventory = Inventory::new(customers);

        group.bench_with_input(
            BenchmarkId::new("lookup", num_customers),
            num_customers,
            |b, _| b.iter(|| black_box(inventory.lookup_ip("203.50.1.1"))),
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_inventory_lookup,
    bench_scope_hash,
    bench_database_operations,
    bench_serialization,
    bench_match_criteria,
    bench_uuid,
    bench_db_scaling,
    bench_inventory_scaling,
);

criterion_main!(benches);
