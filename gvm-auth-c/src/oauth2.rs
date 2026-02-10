// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::set_err;
use crate::strings::rs_string_to_c_ptr;
use std::ffi::{CStr, c_char};
use std::ptr::null_mut;

/// Opaque C wrapper for the Rust OAuth2TokenProvider type.
///
/// This struct is intentionally opaque to C callers. They only interact with it
/// via a raw pointer (`gvm_oauth2_token_provider_t`) and the functions in this module.
#[allow(non_camel_case_types)]
pub struct gvm_oauth2_token_provider {
    p: gvm_auth::oauth2::OAuth2TokenProvider,
}

/// Pointer to an OAuth2 token provider instance.
///
/// Must be created with `gvm_oauth2_token_provider_new` and freed with
/// `gvm_oauth2_token_provider_free`.
#[allow(non_camel_case_types)]
pub type gvm_oauth2_token_provider_t = *mut gvm_oauth2_token_provider;

/// Errors returned by `gvm_oauth2_token_provider_new`.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum gvm_oauth2_new_err_t {
    /// Unspecified internal error
    GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR = -1,
    /// No error
    GVM_OAUTH2_NEW_ERR_OK = 0,
    /// token_url was NULL or empty/invalid
    GVM_OAUTH2_NEW_ERR_NO_TOKEN_URL = 1,
    /// client_id was NULL or empty
    GVM_OAUTH2_NEW_ERR_NO_CLIENT_ID = 2,
    /// client_secret was NULL or empty
    GVM_OAUTH2_NEW_ERR_NO_CLIENT_SECRET = 3,
    /// token_url could not be parsed as a valid URL
    GVM_OAUTH2_NEW_ERR_INVALID_TOKEN_URL = 4,
}

/// Errors returned by `gvm_oauth2_get_token`.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum gvm_oauth2_get_token_err_t {
    /// Unspecified internal error
    GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR = -1,
    /// No error
    GVM_OAUTH2_GET_TOKEN_ERR_OK = 0,
    /// Provider pointer was NULL
    GVM_OAUTH2_GET_TOKEN_ERR_NO_PROVIDER = 1,
    /// HTTP request failed / token endpoint error
    GVM_OAUTH2_GET_TOKEN_ERR_REQUEST_FAILED = 2,
    /// Token response missing `expires_in`
    GVM_OAUTH2_GET_TOKEN_ERR_MISSING_EXPIRES_IN = 3,
}

/// Create a new OAuth2 token provider.
///
/// This provider uses OAuth2 client credentials against `token_url`.
///
/// - `token_url`, `client_id`, `client_secret` must be non-NULL.
/// - `scopes` may be NULL. If not NULL, scopes are parsed from a delimited string
///   (space, comma, or semicolon separated).
/// - `refresh_skew_seconds` controls when the cached token should be refreshed.
///   (Passed through to the Rust provider config.)
///
/// On success:
/// - returns a non-NULL provider pointer
/// - sets `*err` to `GVM_OAUTH2_NEW_ERR_OK` (if `err` is not NULL)
///
/// On failure:
/// - returns NULL
/// - sets `*err` to an appropriate error code (if `err` is not NULL)
///
/// # Safety
/// All pointers must be either NULL or valid and NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_oauth2_token_provider_new(
    token_url: *const c_char,
    client_id: *const c_char,
    client_secret: *const c_char,
    scopes: *const c_char,
    refresh_skew_seconds: u64,
    err: *mut gvm_oauth2_new_err_t,
) -> gvm_oauth2_token_provider_t {
    set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR);

    if token_url.is_null() {
        set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_TOKEN_URL);
        return null_mut();
    }
    if client_id.is_null() {
        set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_ID);
        return null_mut();
    }
    if client_secret.is_null() {
        set_err!(
            err,
            gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_SECRET
        );
        return null_mut();
    }

    let token_url = match unsafe { CStr::from_ptr(token_url).to_str() } {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR);
            return null_mut();
        }
    };

    let client_id = match unsafe { CStr::from_ptr(client_id).to_str() } {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR);
            return null_mut();
        }
    };

    let client_secret = match unsafe { CStr::from_ptr(client_secret).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR);
            return null_mut();
        }
    };

    // Parse optional scopes string into a Vec<String>.
    // Accepted delimiters: space, comma, semicolon.
    let scopes_vec = if scopes.is_null() {
        vec![]
    } else {
        match unsafe { CStr::from_ptr(scopes).to_str() } {
            Ok(s) => s
                .split(|c| c == ' ' || c == ',' || c == ';')
                .map(|x| x.trim())
                .filter(|x| !x.is_empty())
                .map(|x| x.to_string())
                .collect(),
            Err(_) => vec![],
        }
    };

    let config = gvm_auth::oauth2::ClientCredentialsConfig {
        token_url,
        client_id,
        client_secret,
        scopes: scopes_vec,
        refresh_skew_seconds: Some(refresh_skew_seconds),
    };

    let provider = match gvm_auth::oauth2::OAuth2TokenProvider::new(config) {
        Ok(p) => p,
        Err(e) => {
            match e {
                gvm_auth::oauth2::OAuth2TokenProviderError::InvalidConfig(msg) => {
                    // Map Rust config validation errors to stable C error codes.
                    let mapped = if msg.contains("token_url") {
                        gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_TOKEN_URL
                    } else if msg.contains("client_id") {
                        gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_ID
                    } else if msg.contains("client_secret") {
                        gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_SECRET
                    } else {
                        gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR
                    };
                    set_err!(err, mapped);
                }
                gvm_auth::oauth2::OAuth2TokenProviderError::InvalidTokenUrl(_) => {
                    set_err!(
                        err,
                        gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INVALID_TOKEN_URL
                    );
                }
                _ => {
                    set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR);
                }
            }
            return null_mut();
        }
    };

    set_err!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);
    Box::into_raw(Box::new(gvm_oauth2_token_provider { p: provider }))
}

/// Free an OAuth2 token provider.
///
/// # Safety
/// Pointer must be NULL or a valid pointer created by `gvm_oauth2_token_provider_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_oauth2_token_provider_free(p: gvm_oauth2_token_provider_t) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

/// Get an OAuth2 access token (client credentials).
///
/// Returns a newly allocated C string on success.
/// The caller must free the returned string using the appropriate free function
///
/// On error, returns NULL and sets `*err` (if `err` is not NULL).
///
/// # Safety
/// - `p` must be NULL or a valid provider pointer created by `gvm_oauth2_token_provider_new`.
/// - `err` may be NULL.
/// - The returned pointer (if non-NULL) must be freed by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gvm_oauth2_get_token(
    p: gvm_oauth2_token_provider_t,
    err: *mut gvm_oauth2_get_token_err_t,
) -> *mut c_char {
    set_err!(
        err,
        gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR
    );

    if p.is_null() {
        set_err!(
            err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_NO_PROVIDER
        );
        return null_mut();
    }

    match unsafe { (*p).p.get_token() } {
        Ok(tok) => {
            set_err!(err, gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_OK);
            rs_string_to_c_ptr(tok)
        }
        Err(e) => {
            match e {
                gvm_auth::oauth2::OAuth2TokenProviderError::MissingExpiresIn => {
                    set_err!(
                        err,
                        gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_MISSING_EXPIRES_IN
                    );
                }
                gvm_auth::oauth2::OAuth2TokenProviderError::TokenRequest(_) => {
                    set_err!(
                        err,
                        gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_REQUEST_FAILED
                    );
                }
                _ => {
                    set_err!(
                        err,
                        gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR
                    );
                }
            }
            null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use std::ffi::{CStr, CString};
    use std::ptr;

    unsafe fn cstr_to_string(p: *const c_char) -> String {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    #[test]
    fn new_sets_error_on_null_inputs() {
        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        // token_url NULL
        let p = unsafe {
            gvm_oauth2_token_provider_new(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                30,
                &mut err,
            )
        };
        assert!(p.is_null());
        assert_eq!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_TOKEN_URL);

        // client_id NULL
        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;
        let token_url = CString::new("http://127.0.0.1:1/token").unwrap();
        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                30,
                &mut err,
            )
        };
        assert!(p.is_null());
        assert_eq!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_ID);

        // client_secret NULL
        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;
        let client_id = CString::new("id").unwrap();
        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                ptr::null(),
                ptr::null(),
                30,
                &mut err,
            )
        };
        assert!(p.is_null());
        assert_eq!(
            err,
            gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_SECRET
        );
    }

    #[test]
    fn new_maps_invalid_token_url() {
        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        let token_url = CString::new("not a url").unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut err,
            )
        };

        assert!(p.is_null());
        assert_eq!(
            err,
            gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INVALID_TOKEN_URL
        );
    }

    #[test]
    fn new_maps_invalid_config_empty_token_url() {
        use std::ffi::CString;
        use std::ptr;

        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        let token_url = CString::new("").unwrap(); // not NULL, but empty
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut err,
            )
        };

        assert!(p.is_null());
        assert_eq!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_TOKEN_URL);
    }

    #[test]
    fn new_maps_invalid_config_empty_client_id() {
        use std::ffi::CString;
        use std::ptr;

        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        let token_url = CString::new("http://127.0.0.1/token").unwrap();
        let client_id = CString::new("   ").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut err,
            )
        };

        assert!(p.is_null());
        assert_eq!(err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_ID);
    }

    #[test]
    fn new_ignores_invalid_utf8_scopes_and_still_works() {
        use httpmock::prelude::*;
        use std::ffi::CString;
        let server = MockServer::start();

        // Expect a token request WITHOUT a scope parameter
        let m = server.mock(|when, then| {
            when.method(POST).path("/token").body_excludes("scope=");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#);
        });

        let token_url = CString::new(format!("{}/token", server.base_url())).unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let bad_scopes = vec![0xFFu8, 0x00u8];
        let bad_scopes_ptr = bad_scopes.as_ptr() as *const c_char;

        let mut new_err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                bad_scopes_ptr,
                30,
                &mut new_err,
            )
        };

        assert!(!p.is_null());
        assert_eq!(new_err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);

        let mut tok_err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
        let tok_ptr = unsafe { gvm_oauth2_get_token(p, &mut tok_err) };

        assert!(!tok_ptr.is_null());
        assert_eq!(
            tok_err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_OK
        );

        m.assert_calls(1);

        unsafe { crate::strings::gvm_auth_str_free(tok_ptr) };
        unsafe { gvm_oauth2_token_provider_free(p) };
    }

    #[test]
    fn new_parses_scopes_with_commas_spaces_and_semicolons() {
        use httpmock::prelude::*;
        use std::ffi::CString;
        let server = MockServer::start();

        let m = server.mock(|when, then| {
            when.method(POST)
                .path("/token")
                .body_includes("scope=")
                .body_includes("a")
                .body_includes("b")
                .body_includes("c");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#);
        });

        let token_url = CString::new(format!("{}/token", server.base_url())).unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        // Mixed delimiters: space, comma, semicolon
        let scopes = CString::new("a, b;  c  ").unwrap();

        let mut new_err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                scopes.as_ptr(),
                30,
                &mut new_err,
            )
        };

        assert!(!p.is_null());
        assert_eq!(new_err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);

        let mut tok_err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
        let tok_ptr = unsafe { gvm_oauth2_get_token(p, &mut tok_err) };

        assert!(!tok_ptr.is_null());
        assert_eq!(
            tok_err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_OK
        );

        m.assert_calls(1);

        unsafe { crate::strings::gvm_auth_str_free(tok_ptr) };
        unsafe { gvm_oauth2_token_provider_free(p) };
    }

    #[test]
    fn new_maps_invalid_config_empty_client_secret() {
        use std::ffi::CString;
        use std::ptr;

        let mut err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        let token_url = CString::new("http://127.0.0.1/token").unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut err,
            )
        };

        assert!(p.is_null());
        assert_eq!(
            err,
            gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_NO_CLIENT_SECRET
        );
    }

    #[test]
    fn get_token_returns_error_on_null_provider() {
        let mut err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_OK;
        let tok = unsafe { gvm_oauth2_get_token(ptr::null_mut(), &mut err) };

        assert!(tok.is_null());
        assert_eq!(
            err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_NO_PROVIDER
        );
    }

    #[test]
    fn get_token_maps_request_failed_when_server_unreachable() {
        let mut new_err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        let token_url = CString::new("http://127.0.0.1:9/token").unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut new_err,
            )
        };

        assert!(!p.is_null());
        assert_eq!(new_err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);

        let mut tok_err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_OK;
        let tok = unsafe { gvm_oauth2_get_token(p, &mut tok_err) };

        assert!(tok.is_null());
        assert_eq!(
            tok_err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_REQUEST_FAILED
        );

        unsafe { gvm_oauth2_token_provider_free(p) };
    }

    #[test]
    fn get_token_success_returns_c_string() {
        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#);
        });

        let mut new_err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK;

        let token_url = CString::new(format!("{}/token", server.base_url())).unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut new_err,
            )
        };

        assert!(!p.is_null());
        assert_eq!(new_err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);

        let mut tok_err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
        let tok_ptr = unsafe { gvm_oauth2_get_token(p, &mut tok_err) };

        assert!(!tok_ptr.is_null());
        assert_eq!(
            tok_err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_OK
        );

        let tok = unsafe { cstr_to_string(tok_ptr) };
        assert_eq!(tok, "t1");

        unsafe {
            crate::strings::gvm_auth_str_free(tok_ptr);
        }

        unsafe { gvm_oauth2_token_provider_free(p) };
    }
    #[test]
    fn get_token_server_500_maps_to_request_failed() {
        use httpmock::prelude::*;
        use std::ffi::CString;
        use std::ptr;

        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(500)
                .header("content-type", "application/json")
                .body(r#"{"error":"server_error","error_description":"err"}"#);
        });

        let mut new_err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;

        let token_url = CString::new(format!("{}/token", server.base_url())).unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut new_err,
            )
        };

        assert!(!p.is_null());
        assert_eq!(new_err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);

        let mut tok_err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
        let tok_ptr = unsafe { gvm_oauth2_get_token(p, &mut tok_err) };

        assert!(tok_ptr.is_null());
        assert_eq!(
            tok_err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_REQUEST_FAILED
        );

        unsafe { gvm_oauth2_token_provider_free(p) };
    }
    #[test]
    fn get_token_missing_expires_in_maps_to_missing_expires_in_err() {
        use httpmock::prelude::*;
        use std::ffi::CString;
        use std::ptr;

        let server = MockServer::start();

        let _m = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer"}"#);
        });

        let token_url = CString::new(format!("{}/token", server.base_url())).unwrap();
        let client_id = CString::new("id").unwrap();
        let client_secret = CString::new("secret").unwrap();

        let mut new_err = gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
        let p = unsafe {
            gvm_oauth2_token_provider_new(
                token_url.as_ptr(),
                client_id.as_ptr(),
                client_secret.as_ptr(),
                ptr::null(),
                30,
                &mut new_err,
            )
        };

        assert!(!p.is_null());
        assert_eq!(new_err, gvm_oauth2_new_err_t::GVM_OAUTH2_NEW_ERR_OK);

        let mut tok_err = gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
        let tok_ptr = unsafe { gvm_oauth2_get_token(p, &mut tok_err) };

        assert!(tok_ptr.is_null());
        assert_eq!(
            tok_err,
            gvm_oauth2_get_token_err_t::GVM_OAUTH2_GET_TOKEN_ERR_MISSING_EXPIRES_IN
        );

        unsafe { gvm_oauth2_token_provider_free(p) };
    }
}
