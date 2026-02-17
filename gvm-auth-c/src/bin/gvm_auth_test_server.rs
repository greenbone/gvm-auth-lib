// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Minimal HTTP server used by CGreen tests for the gvm-auth-c OAuth2 wrapper.
//!
//! It simulates an OAuth2 token endpoint at POST /token and exits after handling
//! a single request. The response is configured via environment variables:
//! - TEST_HTTP_STATUS: HTTP status code to return (default: 200)
//! - TEST_HTTP_BODY: JSON response body (default: access_token payload)
//! - TEST_HTTP_PORT: bind port (default: 0 for ephemeral)

use std::io::Write;
use std::{env, io};
use tiny_http::{Header, Method, Response, Server};

fn main() {
    let status: u16 = env::var("TEST_HTTP_STATUS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let body = env::var("TEST_HTTP_BODY")
        .unwrap_or(r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#.to_string());

    // If not set, use 0 (ephemeral port).
    let bind_port: u16 = env::var("TEST_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let bind_addr = format!("127.0.0.1:{}", bind_port);

    let server = Server::http(&bind_addr).expect("bind");
    let addr = server.server_addr().to_string();
    let port = addr.split(':').last().unwrap();

    println!("PORT={}", port);
    io::stdout().flush().unwrap();

    let req = server.recv().expect("recv request");

    if req.method() != &Method::Post || req.url() != "/token" {
        let r = Response::from_string(r#"{"error":"not_found"}"#)
            .with_status_code(404)
            .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
        let _ = req.respond(r);
        return;
    }

    let mut resp = Response::from_string(body).with_status_code(status);
    resp.add_header(Header::from_bytes("Content-Type", "application/json").unwrap());

    let _ = req.respond(resp);
}
