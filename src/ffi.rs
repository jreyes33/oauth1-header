use crate::Credentials;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

#[no_mangle]
#[allow(missing_docs)]
pub extern "C" fn auth_header(
    f_consumer_key: *const c_char,
    f_consumer_secret: *const c_char,
    f_token: *const c_char,
    f_token_secret: *const c_char,
    f_method_str: *const c_char,
    f_base_url: *const c_char,
    f_params: *const *const c_char,
    params_count: usize,
) -> *const c_char {
    let consumer_key = to_str(f_consumer_key);
    let consumer_secret = to_str(f_consumer_secret);
    let token = to_str(f_token);
    let token_secret = to_str(f_token_secret);
    let method_str = to_str(f_method_str);
    let base_url = to_str(f_base_url);
    let credentials = Credentials::new(consumer_key, consumer_secret, token, token_secret);
    let method = method_str.try_into().unwrap_or_default();
    let params = to_hash_map(f_params, params_count);
    let result = credentials.auth(&method, base_url, &params);
    let c_string = CString::new(result).unwrap();
    c_string.into_raw()
}

fn to_str<'a>(ptr: *const c_char) -> &'a str {
    let c_str = unsafe {
        assert!(!ptr.is_null());
        CStr::from_ptr(ptr)
    };
    c_str.to_str().unwrap()
}

fn to_hash_map<'a>(ptr: *const *const c_char, len: usize) -> HashMap<&'a str, &'a str> {
    let params_ptr_arr = unsafe {
        assert!(!ptr.is_null());
        slice::from_raw_parts(ptr, len)
    };
    params_ptr_arr
        .chunks_exact(2)
        .map(|pair| (to_str(pair[0]), to_str(pair[1])))
        .collect()
}
