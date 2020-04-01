use criterion::{criterion_group, criterion_main, Criterion};

use oauth1::Token;
use oauth1_header::http::Method;
use oauth1_header::Credentials;
use std::collections::HashMap;

criterion_group!(benches, bench_crates);
criterion_main!(benches);

fn bench_crates(c: &mut Criterion) {
    let mut group = c.benchmark_group("OAuth 1.0 crates");
    group.bench_function("oauth1-header", |b| b.iter(test_this_crate));
    group.bench_function("oauth1", |b| b.iter(test_other_crate));
    group.finish();
}

fn test_this_crate() {
    let mut params = HashMap::new();
    params.insert("foo", "bar");
    let credentials = Credentials::new(
        "some-consumer-key",
        "some-consumer-secret",
        "some-token",
        "some-token-secret",
    );
    let header_value = credentials.auth(&Method::GET, "https://example.com", &params);
    assert_eq!(Some("OAuth"), header_value.get(0..5));
}

fn test_other_crate() {
    let mut params = HashMap::new();
    params.insert("foo", "bar".into());
    let header_value = oauth1::authorize(
        "GET",
        "https://example.com",
        &Token::new("some-consumer-key", "some-consumer-secret"),
        Some(&Token::new("some-token", "some-token-secret")),
        Some(params),
    );
    assert_eq!(Some("OAuth"), header_value.get(0..5));
}
