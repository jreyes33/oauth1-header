use oauth1_header::http::Method;
use oauth1_header::Credentials;
use std::collections::HashMap;

// Placing tests here instead of in the same `src` files allows us to test as
// if we were consumers of the crate.

#[test]
fn it_works() {
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

#[test]
fn test_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Credentials>();
}

#[test]
fn test_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<Credentials>();
}

#[test]
fn test_debug() {
    let debug = format!("{:?}", Credentials::new("ck", "cs", "t", "ts"));
    assert_eq!(Some("Credentials {"), debug.get(0..13));
}
