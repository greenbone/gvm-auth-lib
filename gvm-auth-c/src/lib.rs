// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! #gvm-auth-c-lib
//! The `gvm-auth-c-lib` crate is a wrapper of the GVM authentication library
//! `gvm-auth-lib` for use in C.

#[macro_use]
pub mod jwt;
pub mod strings;
#[macro_use]
pub mod oauth2;
mod c_ffi_macros;
