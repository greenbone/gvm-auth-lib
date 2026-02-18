// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! # gvm-auth-lib
//!
//! The GVM Authentication Library is a Rust library for common authentication
//! functionality used within the Greenbone Vulnerability Manager such as
//! the generation of JSON Web Tokens and communicating with authentication
//! APIs like OAuth and OpenID Connect.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod clock;
pub mod jwt;
pub mod oauth2;
