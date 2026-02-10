// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

extern crate cbindgen;
use build_print::info;
use std::env;
use std::path::Path;

fn main() {
    let profile = env::var("PROFILE").unwrap();
    let cargo_manifest_dir_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let has_headers_feature = env::var("CARGO_FEATURE_HEADERS").is_ok();

    let crate_dir = Path::new(&cargo_manifest_dir_env);
    let workspace_dir = &crate_dir
        .parent()
        .expect("Could not get parent workspace path");
    let build_dir = &workspace_dir.join("target").join(&profile);

    let header_output_path = build_dir.join("gvm_auth.h");

    if has_headers_feature {
        info!(
            "Generating header file ({})...",
            header_output_path.display()
        );
        cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_language(cbindgen::Language::C)
            .with_pragma_once(true)
            .with_include_guard("_GVM_AUTH")
            .with_header(include_str!("c_header_top.txt"))
            .with_documentation(true)
            .generate()
            .expect("Unable to generate C bindings")
            .write_to_file(header_output_path);
    }
}
