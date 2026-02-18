# Copyright (C) 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

add_executable(test-jwt "${AUTH_C_LIB_DIR}/tests/jwt.c")
add_dependencies(test-jwt c-lib)
target_link_libraries(test-jwt ${CGREEN_LIBRARIES} ${C_LIB_BUILD_PATH})
add_test(NAME test-jwt COMMAND test-jwt)

add_executable(test-oauth2 "${AUTH_C_LIB_DIR}/tests/oauth2.c")
target_compile_definitions(
  test-oauth2
  PRIVATE GVM_AUTH_TEST_SERVER_PATH="${RUST_TEST_SERVER_BIN_PATH}"
)
add_dependencies(test-oauth2 c-lib rust-test-server)
target_link_libraries(test-oauth2 ${CGREEN_LIBRARIES} ${C_LIB_BUILD_PATH})
add_test(
  NAME test-oauth2
  COMMAND
    ${CMAKE_COMMAND} -E env GVM_AUTH_TEST_SERVER=${RUST_TEST_SERVER_BIN_PATH}
    $<TARGET_FILE:test-oauth2>
)

add_compile_definitions(TEST_GVM_AUTH_VERSION="${GVM_AUTH_LIB_VERSION}")
add_executable(test-version "${AUTH_C_LIB_DIR}/tests/version.c")
add_dependencies(test-version c-lib)
target_link_libraries(test-version ${CGREEN_LIBRARIES} ${C_LIB_BUILD_PATH})
add_test(NAME test-version COMMAND test-version)

add_custom_target(tests DEPENDS test-jwt test-oauth2 test-version)
