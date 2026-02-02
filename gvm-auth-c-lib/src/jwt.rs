// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::strings::rs_string_to_c_ptr;
use gvm_auth_lib::jwt::{Claims, JwtDecodeSecret, JwtEncodeSecret, generate_token, validate_token};

use chrono::TimeDelta;
use std::ffi::{CStr, c_char, c_int};
use std::ptr::null_mut;

/// Opaque C wrapper for the JwtDecodeSecret type
#[allow(non_camel_case_types)]
pub struct gvm_jwt_decode_secret {
    s: JwtDecodeSecret,
}

/// Opaque C wrapper for the JwtEncodeSecret type
#[allow(non_camel_case_types)]
pub struct gvm_jwt_encode_secret {
    s: JwtEncodeSecret,
}

/// Pointer to a secret to decode JWTs
#[allow(non_camel_case_types)]
pub type gvm_jwt_decode_secret_t = *mut gvm_jwt_decode_secret;

/// Pointer to a secret to encode JWTs
#[allow(non_camel_case_types)]
pub type gvm_jwt_encode_secret_t = *mut gvm_jwt_encode_secret;

/// Enum specifying the type of secret
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum gvm_jwt_secret_type_t {
    GVM_JWT_SECRET_TYPE_SHARED = 1,
    GVM_JWT_SECRET_TYPE_EC_PEM = 2,
    GVM_JWT_SECRET_TYPE_RSA_PEM = 3,
}

/// Create a new JWT decode secret
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_decode_secret(
    secret_type: gvm_jwt_secret_type_t,
    secret_data: *const c_char,
    _secret_data_size: isize,
) -> gvm_jwt_decode_secret_t {
    if secret_data.is_null() {
        return null_mut();
    }

    let inner_secret = match secret_type {
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED => {
            let data_cstr: &CStr = unsafe { CStr::from_ptr(secret_data) };
            let data_str = match data_cstr.to_str() {
                Ok(s) => s,
                Err(_e) => return null_mut(),
            };
            JwtDecodeSecret::from_shared_secret(data_str)
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtDecodeSecret::from_ec_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => return null_mut(),
            }
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtDecodeSecret::from_rsa_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => return null_mut(),
            }
        }
    };

    let boxed_secret = Box::<gvm_jwt_decode_secret>::new(gvm_jwt_decode_secret { s: inner_secret });
    return Box::into_raw(boxed_secret);
}

/// Create a new JWT decode secret from a shared secret
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_shared_decode_secret(
    shared_secret: *const c_char,
) -> gvm_jwt_decode_secret_t {
    return gvm_jwt_new_decode_secret(
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED,
        shared_secret,
        -1,
    );
}

/// Create a new JWT decode secret from ECDSA PEM
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_ec_pem_decode_secret(pem: *const c_char) -> gvm_jwt_decode_secret_t {
    return gvm_jwt_new_decode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM, pem, -1);
}

/// Create a new JWT decode secret from RSA PEM
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_rsa_pem_decode_secret(pem: *const c_char) -> gvm_jwt_decode_secret_t {
    return gvm_jwt_new_decode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM, pem, -1);
}

/// Free a JWT decode secret
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_decode_secret_free(secret: gvm_jwt_decode_secret_t) {
    if !(secret.is_null()) {
        let boxed_secret = unsafe { Box::from_raw(secret) };
        drop(boxed_secret);
    }
}

/// Create a new JWT encode secret
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_encode_secret(
    secret_type: gvm_jwt_secret_type_t,
    secret_data: *const c_char,
    _secret_data_size: isize,
) -> gvm_jwt_encode_secret_t {
    if secret_data.is_null() {
        return null_mut();
    }

    let inner_secret = match secret_type {
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED => {
            let data_cstr: &CStr = unsafe { CStr::from_ptr(secret_data) };
            let data_str = match data_cstr.to_str() {
                Ok(s) => s,
                Err(_e) => return null_mut(),
            };
            JwtEncodeSecret::from_shared_secret(data_str)
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtEncodeSecret::from_ec_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => return null_mut(),
            }
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtEncodeSecret::from_rsa_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => return null_mut(),
            }
        }
    };

    let boxed_secret = Box::<gvm_jwt_encode_secret>::new(gvm_jwt_encode_secret { s: inner_secret });
    return Box::into_raw(boxed_secret);
}

/// Create a new JWT encode secret using a shared secret
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_shared_encode_secret(
    shared_secret: *const c_char,
) -> gvm_jwt_encode_secret_t {
    return gvm_jwt_new_encode_secret(
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED,
        shared_secret,
        -1,
    );
}

/// Create a new JWT encode secret from ECDSA PEM
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_ec_pem_encode_secret(pem: *const c_char) -> gvm_jwt_encode_secret_t {
    return gvm_jwt_new_encode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM, pem, -1);
}

/// Create a new JWT encode secret from RSA PEM
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_rsa_pem_encode_secret(pem: *const c_char) -> gvm_jwt_encode_secret_t {
    return gvm_jwt_new_encode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM, pem, -1);
}

/// Free a JWT encode secret
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_encode_secret_free(secret: gvm_jwt_encode_secret_t) {
    if !(secret.is_null()) {
        let boxed_secret = unsafe { Box::from_raw(secret) };
        drop(boxed_secret);
    }
}

/// Create a JWT for a given secret, username and validity
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_generate_token(
    secret: gvm_jwt_encode_secret_t,
    username: *const c_char,
    valid_seconds: i64,
) -> *mut c_char {
    if secret.is_null() {
        return null_mut();
    }
    let rs_secret = unsafe { &(*secret).s };
    let username_cstr = unsafe { CStr::from_ptr(username) };
    let username_str = match username_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_e) => return null_mut(),
    };

    let time_delta = TimeDelta::seconds(valid_seconds);
    let rs_claims = Claims::new(username_str, time_delta);

    let token = match generate_token(rs_secret, &rs_claims) {
        Ok(s) => s,
        Err(_e) => return null_mut(),
    };
    return rs_string_to_c_ptr(token);
}

/// Validate a JWT with a given secret.
///
/// If a subject is also given, it is compared to the one in the token claims.
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_validate_token(
    secret: gvm_jwt_decode_secret_t,
    token: *const c_char,
    sub: *const c_char,
) -> c_int {
    if secret.is_null() {
        return -1;
    }
    let rs_secret: &JwtDecodeSecret = unsafe { &(*secret).s };
    let token_cstr = unsafe { CStr::from_ptr(token) };
    let token_str = match token_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_e) => return -1,
    };

    let claims: Claims = match validate_token(rs_secret, &token_str) {
        Ok(v) => v,
        Err(_e) => return 1,
    };

    if !(sub.is_null()) {
        let sub_cstr = unsafe { CStr::from_ptr(sub) };
        let sub_str = match sub_cstr.to_str() {
            Ok(s) => s.to_string(),
            Err(_e) => return -1,
        };
        if sub_str != claims.sub {
            return 2;
        }
    }

    return 0;
}
