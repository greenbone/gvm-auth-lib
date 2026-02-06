# Copyright (C) 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.28)
project(gvm_auth_lib)

# Set Rust compiler profile based on build type

if("Release" STREQUAL "${CMAKE_BUILD_TYPE}")
    set(CARGO_PROFILE release)
    set(CARGO_BUILD_CMD cargo build --release)
else()
    set(CARGO_PROFILE debug)
    set(CARGO_BUILD_CMD cargo build)
endif()

# Path variables

set(RUST_BASE_DIR ${CMAKE_SOURCE_DIR})
set(RUST_BUILD_PATH ${RUST_BASE_DIR}/target/${CARGO_PROFILE})

set(AUTH_LIB_DIR ${RUST_BASE_DIR}/gvm-auth)
set(AUTH_C_LIB_DIR ${RUST_BASE_DIR}/gvm-auth-c)

set(C_LIB_FILENAME
    ${CMAKE_SHARED_LIBRARY_PREFIX}gvm_auth${CMAKE_SHARED_LIBRARY_SUFFIX}
)
set(C_LIB_BUILD_PATH ${RUST_BUILD_PATH}/${C_LIB_FILENAME})
set(C_LIB_HEADER_PATH ${RUST_BUILD_PATH}/gvm_auth.h)

set(TEST_DATA_DIR ${CMAKE_SOURCE_DIR}/test-data)
set(TEST_HEADER_PATH ${TEST_DATA_DIR}/test_data.h)

# Rust sources

set(LIB_RUST_SRC_FILES ${AUTH_LIB_DIR}/src/jwt.rs ${AUTH_LIB_DIR}/src/lib.rs)

set(C_LIB_RUST_SRC_FILES
    ${AUTH_C_LIB_DIR}/src/jwt.rs
    ${AUTH_C_LIB_DIR}/src/lib.rs
    ${AUTH_C_LIB_DIR}/src/strings.rs
)

# Rust / Cargo targets

add_custom_command(
    OUTPUT ${C_LIB_BUILD_PATH}
    COMMAND
        ${CARGO_BUILD_CMD} --manifest-path ${RUST_BASE_DIR}/Cargo.toml -p
        gvm-auth-c
    DEPENDS ${LIB_RUST_SRC_FILES} ${C_LIB_RUST_SRC_FILES}
    USES_TERMINAL
)

add_custom_target(c-lib DEPENDS ${C_LIB_BUILD_PATH})

include_directories(${RUST_BUILD_PATH} ${TEST_DATA_DIR})

# C Tests

enable_testing()

add_executable(test-jwt "${AUTH_C_LIB_DIR}/tests/jwt.c")
add_dependencies(test-jwt c-lib)
target_link_libraries(test-jwt cgreen ${C_LIB_BUILD_PATH})
add_test(NAME test-jwt COMMAND test-jwt)

add_custom_target(tests DEPENDS test-jwt)
