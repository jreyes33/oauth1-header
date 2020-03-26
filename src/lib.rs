//! Generate OAuth 1.0 Authorization headers.
//!
//! # Example
//!
//! ```
//! use oauth1_header::http::Method;
//! use oauth1_header::Credentials;
//! use std::collections::HashMap;
//!
//! let mut params = HashMap::new();
//! params.insert("foo", "bar");
//! let credentials = Credentials::new(
//!     "some-consumer-key",
//!     "some-consumer-secret",
//!     "some-token",
//!     "some-token-secret",
//! );
//! let header_value = credentials.auth(&Method::GET, "https://example.com", &params);
//! ```
//!
//! Where `header_value` will contain the [OAuth Protocol Parameters][oauth_pp]
//! ready to be sent in the HTTP Authorization header.
//!
//! [oauth_pp]: https://oauth.net/core/1.0a/#auth_header_authorization

#![warn(missing_docs)]

use hmac::{Hmac, Mac};
pub use http;
use http::Method;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha1::Sha1;
use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasher;
use std::time::{SystemTime, UNIX_EPOCH};

/// The consumer key, consumer secret, token and token secret used in OAuth 1.0.
#[derive(Debug)]
pub struct Credentials<'a> {
    consumer_key: &'a str,
    consumer_secret: &'a str,
    token: &'a str,
    token_secret: &'a str,
}

impl<'a> Credentials<'a> {
    /// Creates a new `Credentials` struct.
    pub fn new(
        consumer_key: &'a str,
        consumer_secret: &'a str,
        token: &'a str,
        token_secret: &'a str,
    ) -> Credentials<'a> {
        Credentials {
            consumer_key,
            consumer_secret,
            token,
            token_secret,
        }
    }

    /// Returns the OAuth Protocol Parameters which will be used as the value
    /// of the HTTP Authorization header.
    pub fn auth<S: BuildHasher>(
        &self,
        method: &Method,
        base_url: &str,
        params: &HashMap<&str, &str, S>,
    ) -> String {
        let nonce_string: String = thread_rng().sample_iter(Alphanumeric).take(32).collect();
        let oauth_header = OAuthHeader {
            credentials: self,
            nonce: nonce_string.as_str(),
            signature_method: "HMAC-SHA1",
            timestamp: current_timestamp(),
            version: "1.0",
            method,
            base_url,
            params,
        };
        oauth_header.to_string()
    }
}

struct OAuthHeader<'a, S: BuildHasher> {
    credentials: &'a Credentials<'a>,
    nonce: &'a str,
    signature_method: &'a str,
    timestamp: u64,
    version: &'a str,
    method: &'a Method,
    base_url: &'a str,
    params: &'a HashMap<&'a str, &'a str, S>,
}

impl<'a, S: BuildHasher> OAuthHeader<'a, S> {
    fn sign(&self) -> String {
        let signature_base = format!(
            "{}&{}&{}",
            self.method,
            percent_encode(self.base_url),
            percent_encode(&self.params_string())
        );
        let key = format!(
            "{}&{}",
            self.credentials.consumer_secret, self.credentials.token_secret
        );
        let mut hmac =
            Hmac::<Sha1>::new_varkey(key.as_bytes()).expect("HMAC can take keys of any size");
        hmac.input(signature_base.as_bytes());
        let signature = hmac.result();
        percent_encode(&base64::encode(signature.code()))
    }

    fn params_string(&self) -> String {
        let timestamp_string = self.timestamp.to_string();
        let mut oauth_params = HashMap::new();
        oauth_params.insert("oauth_consumer_key", self.credentials.consumer_key);
        oauth_params.insert("oauth_nonce", self.nonce);
        oauth_params.insert("oauth_signature_method", "HMAC-SHA1");
        oauth_params.insert("oauth_timestamp", timestamp_string.as_str());
        oauth_params.insert("oauth_token", self.credentials.token);
        oauth_params.insert("oauth_version", "1.0");
        let mut params: Vec<String> = oauth_params
            .iter()
            .chain(self.params.iter())
            .map({ |(&k, &v)| format!("{}={}", percent_encode(k), percent_encode(v)) })
            .collect();
        params.sort();
        params.join("&")
    }
}

impl<'a, S: BuildHasher> fmt::Display for OAuthHeader<'a, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "OAuth oauth_consumer_key=\"{}\", oauth_nonce=\"{}\", oauth_signature=\"{}\", \
                oauth_signature_method=\"{}\", oauth_timestamp=\"{}\", oauth_token=\"{}\", \
                oauth_version=\"{}\"",
            self.credentials.consumer_key,
            self.nonce,
            self.sign(),
            self.signature_method,
            self.timestamp,
            self.credentials.token,
            self.version
        )
    }
}

fn current_timestamp() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 1_234_567_890,
    }
}

// See:
// https://github.com/servo/rust-url/blob/v2.1.0/percent_encoding/lib.rs#L120-L156
// https://github.com/mehcode/oauth1-rs/blob/2b6ae40/src/lib.rs#L73-L84
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_encode(string: &str) -> String {
    utf8_percent_encode(string, ENCODE_SET).to_string()
}
