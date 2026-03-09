// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::strings::rs_string_to_c_ptr;
use gvm_auth::jwt::{Claims, JwtDecodeSecret, JwtEncodeSecret, generate_token, validate_token};

use crate::set_err;
use chrono::TimeDelta;
use std::ffi::{CStr, CString, c_char};
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
    /// Shared secret
    GVM_JWT_SECRET_TYPE_SHARED = 1,
    /// Elliptic Curve PEM
    GVM_JWT_SECRET_TYPE_EC_PEM = 2,
    /// RSA PEM
    GVM_JWT_SECRET_TYPE_RSA_PEM = 3,
}

/// Enum specifying an error from `gvm_jwt_new_decode_secret`
///  or `gvm_jwt_new_encode_secret`
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum gvm_jwt_new_secret_err_t {
    /// Unspecified internal error,
    GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR = -1,
    /// No error, secret created successfully
    GVM_JWT_NEW_SECRET_ERR_OK = 0,
    /// Given data was NULL
    GVM_JWT_NEW_SECRET_ERR_NO_DATA = 1,
    /// Data could not be converted to a String
    GVM_JWT_NEW_SECRET_ERR_STRING_CONVERSION_FAILED = 2,
    /// Data is not a valid EC PEM key
    GVM_JWT_NEW_SECRET_ERR_INVALID_EC_PEM = 3,
    /// Data is not a valid RSA PEM key
    GVM_JWT_NEW_SECRET_ERR_INVALID_RSA_PEM = 4,
}

/// Returns a string describing a given gvm_jwt_new_secret_err_t
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_new_secret_strerror(
    err: gvm_jwt_new_secret_err_t,
) -> *const c_char {
    let err_int = err as i32;
    if err_int < -1 || err_int > 4 {
       return const_cstr!("unknown error").as_ptr()
    }

    match err {
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR => {
            const_cstr!("internal error").as_ptr()
        }
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_OK => {
            const_cstr!("ok").as_ptr()
        }
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_NO_DATA => {
            const_cstr!("no secret data given").as_ptr()
        }
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_STRING_CONVERSION_FAILED => {
            const_cstr!("data could not be converted to a string").as_ptr()
        }
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INVALID_EC_PEM => {
            const_cstr!("data is not valid ECDSA PEM").as_ptr()
        }
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INVALID_RSA_PEM => {
            const_cstr!("data is not valid RSA PEM key").as_ptr()
        }
    }
}

/// Create a new JWT decode secret
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_decode_secret(
    secret_type: gvm_jwt_secret_type_t,
    secret_data: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_decode_secret_t {
    set_err!(
        err,
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR
    );

    if secret_data.is_null() {
        set_err!(
            err,
            gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_NO_DATA
        );
        return null_mut();
    }

    let inner_secret = match secret_type {
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED => {
            let data_cstr: &CStr = unsafe { CStr::from_ptr(secret_data) };
            let data_str = match data_cstr.to_str() {
                Ok(s) => s,
                Err(_e) => {
                    set_err!(
                        err,
                        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_STRING_CONVERSION_FAILED
                    );
                    return null_mut();
                }
            };
            JwtDecodeSecret::from_shared_secret(data_str)
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtDecodeSecret::from_ec_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => {
                    set_err!(
                        err,
                        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INVALID_EC_PEM
                    );
                    return null_mut();
                }
            }
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtDecodeSecret::from_rsa_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => {
                    set_err!(
                        err,
                        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INVALID_RSA_PEM
                    );
                    return null_mut();
                }
            }
        }
    };

    let boxed_secret = Box::<gvm_jwt_decode_secret>::new(gvm_jwt_decode_secret { s: inner_secret });
    set_err!(err, gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_OK);

    Box::into_raw(boxed_secret)
}

/// Create a new JWT decode secret from a shared secret
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_shared_decode_secret(
    shared_secret: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_decode_secret_t {
    unsafe {
        gvm_jwt_new_decode_secret(
            gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED,
            shared_secret,
            err,
        )
    }
}

/// Create a new JWT decode secret from ECDSA PEM
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_ec_pem_decode_secret(
    pem: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_decode_secret_t {
    unsafe {
        gvm_jwt_new_decode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM, pem, err)
    }
}

/// Create a new JWT decode secret from RSA PEM
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_rsa_pem_decode_secret(
    pem: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_decode_secret_t {
    unsafe {
        gvm_jwt_new_decode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM, pem, err)
    }
}

/// Free a JWT decode secret
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_decode_secret_free(secret: gvm_jwt_decode_secret_t) {
    if !(secret.is_null()) {
        let boxed_secret = unsafe { Box::from_raw(secret) };
        drop(boxed_secret);
    }
}

/// Create a new JWT encode secret
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_encode_secret(
    secret_type: gvm_jwt_secret_type_t,
    secret_data: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_encode_secret_t {
    set_err!(
        err,
        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR
    );

    if secret_data.is_null() {
        set_err!(
            err,
            gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_NO_DATA
        );
        return null_mut();
    }

    let inner_secret = match secret_type {
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED => {
            let data_cstr: &CStr = unsafe { CStr::from_ptr(secret_data) };
            let data_str = match data_cstr.to_str() {
                Ok(s) => s,
                Err(_e) => {
                    set_err!(
                        err,
                        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_STRING_CONVERSION_FAILED
                    );
                    return null_mut();
                }
            };
            JwtEncodeSecret::from_shared_secret(data_str)
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtEncodeSecret::from_ec_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => {
                    set_err!(
                        err,
                        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INVALID_EC_PEM
                    );
                    return null_mut();
                }
            }
        }
        gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM => {
            let data_cstr = unsafe { CStr::from_ptr(secret_data) };
            let data_bytes: &[u8] = data_cstr.to_bytes();
            match JwtEncodeSecret::from_rsa_pem(data_bytes) {
                Ok(s) => s,
                Err(_e) => {
                    set_err!(
                        err,
                        gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_INVALID_RSA_PEM
                    );
                    return null_mut();
                }
            }
        }
    };

    let boxed_secret = Box::<gvm_jwt_encode_secret>::new(gvm_jwt_encode_secret { s: inner_secret });
    set_err!(err, gvm_jwt_new_secret_err_t::GVM_JWT_NEW_SECRET_ERR_OK);

    Box::into_raw(boxed_secret)
}

/// Create a new JWT encode secret using a shared secret
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_shared_encode_secret(
    shared_secret: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_encode_secret_t {
    unsafe {
        gvm_jwt_new_encode_secret(
            gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_SHARED,
            shared_secret,
            err,
        )
    }
}

/// Create a new JWT encode secret from ECDSA PEM
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_ec_pem_encode_secret(
    pem: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_encode_secret_t {
    unsafe {
        gvm_jwt_new_encode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_EC_PEM, pem, err)
    }
}

/// Create a new JWT encode secret from RSA PEM
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_new_rsa_pem_encode_secret(
    pem: *const c_char,
    err: *mut gvm_jwt_new_secret_err_t,
) -> gvm_jwt_encode_secret_t {
    unsafe {
        gvm_jwt_new_encode_secret(gvm_jwt_secret_type_t::GVM_JWT_SECRET_TYPE_RSA_PEM, pem, err)
    }
}

/// Free a JWT encode secret
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_encode_secret_free(secret: gvm_jwt_encode_secret_t) {
    if !(secret.is_null()) {
        let boxed_secret = unsafe { Box::from_raw(secret) };
        drop(boxed_secret);
    }
}

/// Enum specifying an error from `gvm_jwt_generate_token`
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum gvm_jwt_generate_token_err_t {
    /// Unspecified internal error
    GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR = -1,
    /// No error, secret created successfully
    GVM_JWT_GENERATE_TOKEN_ERR_OK = 0,
    /// Given secret was NULL
    GVM_JWT_GENERATE_TOKEN_ERR_NO_SECRET = 1,
    /// Username could not be converted to a String
    GVM_JWT_GENERATE_TOKEN_ERR_INVALID_USER_ID = 2,
    /// Failed to generate token
    GVM_JWT_GENERATE_TOKEN_ERR_GENERATE_FAILED = 3,
}

/// Returns a string describing a given gvm_jwt_generate_token_err_t
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_generate_token_strerror(
    err: gvm_jwt_generate_token_err_t,
) -> *const c_char {
    let err_int = err as i32;
    if err_int < -1 || err_int > 3 {
       return const_cstr!("unknown error").as_ptr()
    }

    match err {
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR => {
            const_cstr!("internal error").as_ptr()
        }
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_OK => {
            const_cstr!("ok").as_ptr()
        }
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_NO_SECRET => {
            const_cstr!("no secret given").as_ptr()
        }
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_INVALID_USER_ID => {
            const_cstr!("username could not be converted to a string").as_ptr()
        }
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_GENERATE_FAILED => {
            const_cstr!("failed to generate token").as_ptr()
        }
    }
}

/// Create a JWT for a given secret, user_id and validity
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_generate_token(
    secret: gvm_jwt_encode_secret_t,
    user_id: *const c_char,
    valid_seconds: i64,
    err: *mut gvm_jwt_generate_token_err_t,
) -> *mut c_char {
    set_err!(
        err,
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR
    );

    if secret.is_null() {
        set_err!(
            err,
            gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_NO_SECRET
        );
        return null_mut();
    }
    let rs_secret = unsafe { &(*secret).s };
    let sub = unsafe { CStr::from_ptr(user_id) };
    let sub = match sub.to_str() {
        Ok(s) => s.to_string(),
        Err(_e) => {
            set_err!(
                err,
                gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_INVALID_USER_ID
            );
            return null_mut();
        }
    };

    let time_delta = TimeDelta::seconds(valid_seconds);
    let rs_claims = Claims::new(sub, time_delta);

    let token = match generate_token(rs_secret, &rs_claims) {
        Ok(s) => s,
        Err(_e) => return null_mut(),
    };

    set_err!(
        err,
        gvm_jwt_generate_token_err_t::GVM_JWT_GENERATE_TOKEN_ERR_OK
    );
    rs_string_to_c_ptr(token)
}

/// Opaque C wrapper for the Claims type
#[allow(non_camel_case_types)]
pub struct gvm_jwt_claims {
    /// Original Rust claims structure
    c: Claims,
    /// Subject converted to a C string
    sub: *mut c_char,
}

/// Opaque pointer to a JWT Claims data structure
#[allow(non_camel_case_types)]
pub type gvm_jwt_claims_t = *mut gvm_jwt_claims;

/// Free a JWT claims data structure
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_claims_free(claims: gvm_jwt_claims_t) {
    if !(claims.is_null()) {
        // let sub = unsafe { CString::from_raw((*claims).sub) };
        // drop (sub);
        let boxed_claims = unsafe { Box::from_raw(claims) };
        drop(boxed_claims);
    }
}

/// Get the expiration time from JWT claims
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_claims_get_exp(claims: gvm_jwt_claims_t) -> u64 {
    if claims.is_null() {
        return 0;
    }
    unsafe {
        (*claims).c.get_exp()
    }
}

/// Get the "issued at" time from JWT claims
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_claims_get_iat(claims: gvm_jwt_claims_t) -> u64 {
    if claims.is_null() {
        return 0;
    }
    unsafe {
        (*claims).c.get_iat()
    }
}

/// Get the expiration time from JWT claims
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_claims_get_sub(claims: gvm_jwt_claims_t) -> *const c_char {
    if claims.is_null() {
        return null_mut();
    }
    unsafe {
        (*claims).sub
    }
}

/// Enum specifying an error from `gvm_jwt_validate_token
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum gvm_jwt_validate_token_err_t {
    /// Unspecified internal error
    GVM_JWT_VALIDATE_TOKEN_ERR_INTERNAL_ERROR = -1,
    /// No error, secret created successfully
    GVM_JWT_VALIDATE_TOKEN_ERR_OK = 0,
    /// Given secret was NULL
    GVM_JWT_VALIDATE_TOKEN_ERR_NO_SECRET = 1,
    /// Given token was NULL
    GVM_JWT_VALIDATE_TOKEN_ERR_NO_TOKEN = 2,
    /// Failed to validate token
    GVM_JWT_VALIDATE_TOKEN_ERR_VALIDATION_FAILED = 3,
    /// Token claims do not match expected structure
    GVM_JWT_VALIDATE_TOKEN_MALFORMED_CLAIMS = 4,
}

/// Returns a string describing a given gvm_jwt_validate_token_err_t
#[unsafe(no_mangle)]
pub extern "C" fn gvm_jwt_validate_token_strerror(
    err: gvm_jwt_validate_token_err_t,
) -> *const c_char {
    let err_int = err as i32;
    if err_int < -1 || err_int > 5 {
       return const_cstr!("unknown error").as_ptr()
    }

    match err {
        gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_INTERNAL_ERROR => {
            const_cstr!("internal error").as_ptr()
        }
        gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_OK => {
            const_cstr!("ok").as_ptr()
        }
        gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_SECRET => {
            const_cstr!("no secret given").as_ptr()
        }
        gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_TOKEN => {
            const_cstr!("no token given").as_ptr()
        }
        gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_VALIDATION_FAILED => {
            const_cstr!("failed to validate token").as_ptr()
        }
        gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_MALFORMED_CLAIMS => {
            const_cstr!("token claims do not match expected structure").as_ptr()
        }
    }
}

/// Validate a JWT with a given secret.
///
/// If a non-null claims_out pointer is also given, the referenced struct
/// will be updated with the claims from the token if it is valid.
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_validate_token(
    secret: gvm_jwt_decode_secret_t,
    token: *const c_char,
    claims_out: *mut gvm_jwt_claims_t,
) -> gvm_jwt_validate_token_err_t {
    if secret.is_null() {
        return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_SECRET;
    }

    if token.is_null() {
        return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_TOKEN;
    }

    let rs_secret: &JwtDecodeSecret = unsafe { &(*secret).s };
    let token_cstr = unsafe { CStr::from_ptr(token) };
    let token_str = match token_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_e) => return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_TOKEN,
    };

    let inner_claims: Claims = match validate_token(rs_secret, &token_str) {
        Ok(v) => v,
        Err(_e) => {
            return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_VALIDATION_FAILED;
        }
    };

    if !(claims_out.is_null()) {
        unsafe {
            let sub = match CString::new(inner_claims.get_sub()) {
                Ok(v) => v,
                Err(_e) => {
                    return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_MALFORMED_CLAIMS;
                }
            };
            let c_claims = gvm_jwt_claims {
                c: inner_claims,
                sub: sub.into_raw(),
            };
            let boxed_claims = Box::<gvm_jwt_claims>::new(c_claims);
            *claims_out = Box::<gvm_jwt_claims>::into_raw(boxed_claims);
        }
    }

    gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_OK
}
