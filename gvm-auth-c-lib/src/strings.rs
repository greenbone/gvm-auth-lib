// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::ffi::{CString, c_char};
use std::ptr::null_mut;

/// Free a string created by rs_string_to_c_ptr / CString::from_raw.
#[unsafe(no_mangle)]
pub extern "C" fn gvm_auth_str_free(ptr: *mut c_char) {
    if !(ptr.is_null()) {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Convert a Rust String into a C string, returning NULL on failure.
pub fn rs_string_to_c_ptr(value: String) -> *mut c_char {
    let c_string: CString = match CString::new(value) {
        Ok(s) => s,
        Err(_e) => return null_mut(),
    };
    return c_string.into_raw();
}
