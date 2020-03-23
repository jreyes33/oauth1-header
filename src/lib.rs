use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha1::Sha1;
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn auth(
    method: &str,
    base_url: &str,
    credentials: &Credentials,
    params: &HashMap<&str, &str>,
) -> String {
    let nonce_string: String = thread_rng().sample_iter(Alphanumeric).take(32).collect();
    let oauth_header = OAuthHeader {
        credentials: credentials,
        nonce: nonce_string.as_str(),
        signature_method: "HMAC-SHA1",
        timestamp: current_timestamp(),
        version: "1.0",
        method: method,
        base_url: base_url,
        params: params,
    };
    oauth_header.to_string()
}

pub struct Credentials {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub access_token: String,
    pub access_token_secret: String,
}

struct OAuthHeader<'a> {
    credentials: &'a Credentials,
    nonce: &'a str,
    signature_method: &'a str,
    timestamp: u64,
    version: &'a str,
    method: &'a str,
    base_url: &'a str,
    params: &'a HashMap<&'a str, &'a str>,
}

impl<'a> OAuthHeader<'a> {
    fn sign(&self) -> String {
        let signature_base = format!(
            "{}&{}&{}",
            self.method,
            percent_encode(self.base_url),
            percent_encode(self.params_string())
        );
        let key = format!(
            "{}&{}",
            self.credentials.consumer_secret, self.credentials.access_token_secret
        );
        let mut hmac =
            Hmac::<Sha1>::new_varkey(key.as_bytes()).expect("HMAC can take keys of any size");
        hmac.input(signature_base.as_bytes());
        let signature = hmac.result();
        percent_encode(base64::encode(signature.code()))
    }

    fn params_string(&self) -> String {
        let timestamp_string = self.timestamp.to_string();
        let mut oauth_params = HashMap::new();
        oauth_params.insert("oauth_consumer_key", self.credentials.consumer_key.as_str());
        oauth_params.insert("oauth_nonce", self.nonce);
        oauth_params.insert("oauth_signature_method", "HMAC-SHA1");
        oauth_params.insert("oauth_timestamp", timestamp_string.as_str());
        oauth_params.insert("oauth_token", self.credentials.access_token.as_str());
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

impl<'a> fmt::Display for OAuthHeader<'a> {
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
            self.credentials.access_token,
            self.version
        )
    }
}

fn current_timestamp() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 1234567890,
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

fn percent_encode<S: Into<String>>(string: S) -> String {
    utf8_percent_encode(&string.into(), ENCODE_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let credentials = Credentials {
            consumer_key: "some-key".to_string(),
            consumer_secret: "some-secret".to_string(),
            access_token: "some-key".to_string(),
            access_token_secret: "some-secret".to_string(),
        };
        let mut params = HashMap::new();
        params.insert("foo", "bar");
        let result = auth("GET", "https://example.com", &credentials, &params);
        assert_eq!(Some("OAuth"), result.get(0..5));
    }
}
