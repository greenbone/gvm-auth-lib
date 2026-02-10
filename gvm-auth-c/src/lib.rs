// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! #gvm-auth-c-lib
//! The `gvm-auth-c-lib` crate is a wrapper of the GVM authentication library
//! `gvm-auth-lib` for use in C.

pub mod jwt;
pub mod strings;
pub mod oauth2;
mod c_ffi_macros;
