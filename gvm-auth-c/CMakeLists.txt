# Copyright (C) 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set(RUST_BASE_DIR ${CMAKE_SOURCE_DIR})

file(STRINGS "${RUST_BASE_DIR}/Cargo.toml" CARGO_TOML_CONTENT)
foreach(line ${CARGO_TOML_CONTENT})
  string(REGEX REPLACE "^version = \"(.*)\"" "\\1" GVM_AUTH_LIB_VERSION ${line})
  if(NOT ${CMAKE_MATCH_COUNT} EQUAL 0)
    # stop on the first regex match, this should be the right version
    break()
  endif()
endforeach()

if(NOT GVM_AUTH_LIB_VERSION)
  message(
    FATAL_ERROR
    "Could not extract version from ${RUST_BASE_DIR}/Cargo.toml"
  )
endif()

project(gvm-auth-lib VERSION ${GVM_AUTH_LIB_VERSION} LANGUAGES C)

## Retrieve git revision (at configure time)
find_package(Git)

include(MacroGitGetRevision)

if(
  NOT CMAKE_BUILD_TYPE STREQUAL "Release"
  AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo"
)
  if(EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if(GIT_FOUND)
      git_get_revision(${CMAKE_SOURCE_DIR} ProjectRevision)
      set(GIT_REVISION "~git-${ProjectRevision}")
    else(GIT_FOUND)
      set(GIT_REVISION "~git")
    endif(GIT_FOUND)
  endif(EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif()

set(
  PROJECT_VERSION_STRING
  "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}${GIT_REVISION}"
)

message(STATUS "Building gvm-auth-lib v${PROJECT_VERSION_STRING}")

# Set Rust compiler profile based on build type

if(
  CMAKE_BUILD_TYPE STREQUAL "Release"
  OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo"
)
  set(CARGO_PROFILE release)
  set(CARGO_BUILD_CMD cargo build --release)
else()
  set(CARGO_PROFILE debug)
  set(CARGO_BUILD_CMD cargo build)
endif()

# Path variables

set(RUST_BUILD_PATH ${RUST_BASE_DIR}/target/${CARGO_PROFILE})

set(AUTH_LIB_DIR ${RUST_BASE_DIR}/gvm-auth)
set(AUTH_C_LIB_DIR ${RUST_BASE_DIR}/gvm-auth-c)

set(
  C_LIB_FILENAME
  ${CMAKE_SHARED_LIBRARY_PREFIX}gvm_auth${CMAKE_SHARED_LIBRARY_SUFFIX}
)
set(C_LIB_BUILD_PATH ${RUST_BUILD_PATH}/${C_LIB_FILENAME})
set(C_LIB_HEADER_PATH ${RUST_BUILD_PATH}/gvm-auth.h)

set(TEST_DATA_DIR ${CMAKE_SOURCE_DIR}/test-data)
set(TEST_HEADER_PATH ${TEST_DATA_DIR}/test_data.h)

set(RUST_TEST_SERVER_BIN_NAME gvm-auth-test-server${CMAKE_EXECUTABLE_SUFFIX})
set(RUST_TEST_SERVER_BIN_PATH ${RUST_BUILD_PATH}/${RUST_TEST_SERVER_BIN_NAME})

# Rust sources

file(
  GLOB_RECURSE LIB_RUST_SRC_FILES
  ${AUTH_LIB_DIR}/Cargo.toml
  ${AUTH_LIB_DIR}/src/**.rs
)
set(LIB_RUST_SRC_FILES ${AUTH_LIB_DIR}/src/jwt.rs ${AUTH_LIB_DIR}/src/lib.rs)

file(
  GLOB_RECURSE C_LIB_RUST_SRC_FILES
  ${AUTH_C_LIB_DIR}/c_header_top.txt
  ${AUTH_C_LIB_DIR}/Cargo.toml
  ${AUTH_C_LIB_DIR}/build.rs
  ${AUTH_C_LIB_DIR}/src/**.rs
)

# Rust / Cargo targets

add_custom_command(
  OUTPUT ${C_LIB_BUILD_PATH}
  COMMAND
    ${CARGO_BUILD_CMD} --manifest-path ${RUST_BASE_DIR}/Cargo.toml -p gvm-auth-c
  DEPENDS
    ${RUST_BASE_DIR}/Cargo.toml
    ${LIB_RUST_SRC_FILES}
    ${C_LIB_RUST_SRC_FILES}
  USES_TERMINAL
)

add_custom_target(c-lib DEPENDS ${C_LIB_BUILD_PATH})

include_directories(${RUST_BUILD_PATH} ${TEST_DATA_DIR})

add_custom_command(
  OUTPUT ${RUST_TEST_SERVER_BIN_PATH}
  COMMAND
    ${CARGO_BUILD_CMD} --manifest-path ${RUST_BASE_DIR}/Cargo.toml -p gvm-auth-c
    --bin gvm-auth-test-server
  DEPENDS ${AUTH_C_LIB_DIR}/src/bin/gvm_auth_test_server.rs
  USES_TERMINAL
)

add_custom_target(rust-test-server DEPENDS ${RUST_TEST_SERVER_BIN_PATH})

# Installation

if(NOT LIBDIR)
  set(_DEFAULT_LIBRARY_INSTALL_DIR lib)
  if(EXISTS "${CMAKE_INSTALL_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(_DEFAULT_LIBRARY_INSTALL_DIR lib32)
  endif(EXISTS "${CMAKE_INSTALL_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  if(EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_DEFAULT_LIBRARY_INSTALL_DIR lib64)
  endif(EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(LIBDIR "${_DEFAULT_LIBRARY_INSTALL_DIR}")
endif(NOT LIBDIR)

if(NOT EXEC_PREFIX)
  set(EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif(NOT EXEC_PREFIX)

if(NOT INCLUDEDIR)
  set(INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif(NOT INCLUDEDIR)

install(FILES ${C_LIB_BUILD_PATH} DESTINATION ${LIBDIR})

install(FILES ${C_LIB_HEADER_PATH} DESTINATION "${INCLUDEDIR}/gvm/auth")

configure_file(
  ${AUTH_C_LIB_DIR}/libgvm_auth.pc.in
  ${CMAKE_BINARY_DIR}/libgvm_auth.pc
  @ONLY
)

install(
  FILES ${CMAKE_BINARY_DIR}/libgvm_auth.pc
  DESTINATION ${LIBDIR}/pkgconfig
)

# C Tests
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
