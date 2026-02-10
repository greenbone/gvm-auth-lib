// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-3.0-or-later

/// Macro to set error return value
#[macro_export]
macro_rules! set_err {
    ($err: expr, $val: expr) => {
        if !($err.is_null()) {
            unsafe {
                *$err = $val;
            }
        }
    };
}
