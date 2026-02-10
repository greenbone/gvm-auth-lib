// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::strings::rs_string_to_c_ptr;
use gvm_auth::jwt::{Claims, JwtDecodeSecret, JwtEncodeSecret, generate_token, validate_token};

use chrono::TimeDelta;
use std::ffi::{CStr, c_char};
use std::ptr::null_mut;

/// Macro to set error return value
macro_rules! set_err {
    ($err: expr, $val: expr) => {
        if !($err.is_null()) {
            unsafe {
                *$err = $val;
            }
        }
    };
}

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

/// Enum specifying an error from `gvm_jwt_validate_token
#[repr(C)]
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
    /// User id could not be converted to a String
    GVM_JWT_VALIDATE_TOKEN_ERR_INVALID_USER_ID = 4,
    /// User id does not match subject in token claims
    GVM_JWT_VALIDATE_TOKEN_ERR_USER_ID_MISMATCH = 5,
}

/// Validate a JWT with a given secret.
///
/// If a user_id is also given, it is compared to the subject
/// in the token claims.
///
/// # Safety
/// Pointers must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_jwt_validate_token(
    secret: gvm_jwt_decode_secret_t,
    token: *const c_char,
    user_id: *const c_char,
) -> gvm_jwt_validate_token_err_t {
    if secret.is_null() {
        return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_SECRET;
    }
    let rs_secret: &JwtDecodeSecret = unsafe { &(*secret).s };
    let token_cstr = unsafe { CStr::from_ptr(token) };
    let token_str = match token_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_e) => return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_NO_TOKEN,
    };

    let claims: Claims = match validate_token(rs_secret, &token_str) {
        Ok(v) => v,
        Err(_e) => {
            return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_VALIDATION_FAILED;
        }
    };

    if !(user_id.is_null()) {
        let sub = unsafe { CStr::from_ptr(user_id) };
        let sub = match sub.to_str() {
            Ok(s) => s.to_string(),
            Err(_e) => {
                return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_INVALID_USER_ID;
            }
        };
        if sub != claims.sub {
            return gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_USER_ID_MISMATCH;
        }
    }

    gvm_jwt_validate_token_err_t::GVM_JWT_VALIDATE_TOKEN_ERR_OK
}
