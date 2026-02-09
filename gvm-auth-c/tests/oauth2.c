/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Tests of the OAuth2 C functions.
 */

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <errno.h>
#include <gvm_auth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

Describe (oauth2);
BeforeEach (oauth2)
{
}
AfterEach (oauth2)
{
}

/*
 * Keep popen handle alive until after one request (server exits after 1 req).
 */
static FILE *g_server_fp = NULL;

/**
 * @brief Get the OAuth2 test server binary path.
 *
 * This function first checks the runtime environment variable
 * @c GVM_AUTH_TEST_SERVER. If not set, it falls back to the compile-time macro
 * @c GVM_AUTH_TEST_SERVER_PATH.
 *
 * @return Absolute/relative path to the test server binary, or NULL if not set.
 */
static const char *
get_server_bin (void)
{
  const char *p = getenv ("GVM_AUTH_TEST_SERVER");
  if (p && *p)
    return p;

#ifdef GVM_AUTH_TEST_SERVER_PATH
  return GVM_AUTH_TEST_SERVER_PATH;
#else
  return NULL;
#endif
}

/**
 * @brief Build a command string for launching the Rust test server via popen().
 *
 * @param[out] dst Buffer to write the command into.
 * @param[in]  dst_len Size of @p dst in bytes.
 * @param[in]  bin_path Path to the server binary.
 * @param[in]  fixed_port Optional port string (e.g. "18081"), or NULL/empty
 *                        to use an ephemeral port.
 *
 * @return 0 on success, -1 on failure.
 */
static int
build_server_cmd (char *dst, size_t dst_len, const char *bin_path,
                  const char *fixed_port)
{
  if (!dst || dst_len == 0 || !bin_path || !*bin_path)
    return -1;

  if (fixed_port && *fixed_port)
    {
      int n = snprintf (dst, dst_len, "TEST_HTTP_PORT=%s \"%s\"", fixed_port,
                        bin_path);
      return (n > 0 && (size_t) n < dst_len) ? 0 : -1;
    }

  int n = snprintf (dst, dst_len, "\"%s\"", bin_path);
  return (n > 0 && (size_t) n < dst_len) ? 0 : -1;
}

/**
 * @brief Start the Rust OAuth2 test server and return the bound port.
 *
 * The response returned by the server is configured using environment
 * variables:
 * - @c TEST_HTTP_STATUS : HTTP status code (e.g. 200, 500)
 * - @c TEST_HTTP_BODY   : JSON response body
 *
 * On success, @p *out_port is set to the actual bound port (as printed by the
 * server).
 *
 * @param[in] status HTTP status code to return.
 * @param[in] json_body JSON body returned by the server.
 * @param[in,out] out_port Input: optional requested port (>0).
 *                         Output: actual port.
 *
 * @return 0 on success, -1 on failure.
 */
static int
start_rust_test_server (int status, const char *json_body, int *out_port)
{
  const char *server_bin = get_server_bin ();

  fprintf (stderr, "oauth2-test: server_bin=%s\n",
           server_bin ? server_bin : "(null)");

  if (!server_bin || !*server_bin || !json_body || !out_port)
    return -1;

  /* If caller sets *out_port > 0, use it as a fixed port. */
  int requested_port = *out_port;

  *out_port = 0;

  /* Make sure previous handle is closed */
  if (g_server_fp)
    {
      pclose (g_server_fp);
      g_server_fp = NULL;
    }

  char status_buf[32];
  snprintf (status_buf, sizeof (status_buf), "%d", status);
  setenv ("TEST_HTTP_STATUS", status_buf, 1);
  setenv ("TEST_HTTP_BODY", json_body, 1);

  char req_port_buf[16];
  const char *fixed_port = NULL;

  if (requested_port > 0)
    {
      snprintf (req_port_buf, sizeof (req_port_buf), "%d", requested_port);
      setenv ("TEST_HTTP_PORT", req_port_buf, 1);
      fixed_port = req_port_buf;
    }
  else
    {
      fixed_port = getenv ("TEST_HTTP_PORT"); /* may be NULL */
    }

  char cmd[1024];
  if (build_server_cmd (cmd, sizeof (cmd), server_bin, fixed_port) != 0)
    {
      fprintf (stderr, "oauth2-test: failed to build popen cmd\n");
      return -1;
    }

  fprintf (stderr, "oauth2-test: popen cmd=%s\n", cmd);

  g_server_fp = popen (cmd, "r");
  if (!g_server_fp)
    {
      fprintf (stderr, "oauth2-test: popen failed: %s\n", strerror (errno));
      return -1;
    }

  char line[256] = {0};
  if (!fgets (line, sizeof (line), g_server_fp))
    {
      fprintf (stderr, "oauth2-test: failed to read PORT line from server\n");
      pclose (g_server_fp);
      g_server_fp = NULL;
      return -1;
    }

  int port = 0;
  if (sscanf (line, "PORT=%d", &port) != 1 || port <= 0)
    {
      fprintf (stderr, "oauth2-test: invalid PORT line: '%s'\n", line);
      pclose (g_server_fp);
      g_server_fp = NULL;
      return -1;
    }

  *out_port = port;
  fprintf (stderr, "oauth2-test: server_port=%d\n", port);
  return 0;
}

/**
 * @brief Stop the Rust test server process (if running).
 */
static void
stop_rust_test_server (void)
{
  if (g_server_fp)
    {
      pclose (g_server_fp);
      g_server_fp = NULL;
    }
}

/**
 * @brief Create a token endpoint URL for the local test server.
 *
 * Writes a URL like @c http://127.0.0.1:<port>/token into @p dst.
 *
 * @param[out] dst Destination buffer.
 * @param[in]  dst_len Size of @p dst in bytes.
 * @param[in]  port TCP port where the test server is listening.
 */
static void
create_token_url (char *dst, size_t dst_len, int port)
{
  snprintf (dst, dst_len, "http://127.0.0.1:%d/token", port);
}

Ensure (oauth2, new_sets_error_on_null_inputs)
{
  gvm_oauth2_new_err_t err = GVM_OAUTH2_NEW_ERR_OK;
  gvm_oauth2_token_provider_t p;

  p = gvm_oauth2_token_provider_new (NULL, NULL, NULL, NULL, 30, &err);
  assert_that (p, is_null);
  assert_that (err, is_equal_to (GVM_OAUTH2_NEW_ERR_NO_TOKEN_URL));

  err = GVM_OAUTH2_NEW_ERR_OK;
  p = gvm_oauth2_token_provider_new ("http://127.0.0.1:1/token", NULL, NULL,
                                     NULL, 30, &err);
  assert_that (p, is_null);
  assert_that (err, is_equal_to (GVM_OAUTH2_NEW_ERR_NO_CLIENT_ID));

  err = GVM_OAUTH2_NEW_ERR_OK;
  p = gvm_oauth2_token_provider_new ("http://127.0.0.1:1/token", "id", NULL,
                                     NULL, 30, &err);
  assert_that (p, is_null);
  assert_that (err, is_equal_to (GVM_OAUTH2_NEW_ERR_NO_CLIENT_SECRET));
}

Ensure (oauth2, new_maps_invalid_token_url)
{
  gvm_oauth2_new_err_t err = GVM_OAUTH2_NEW_ERR_OK;

  gvm_oauth2_token_provider_t p =
    gvm_oauth2_token_provider_new ("not a url", "id", "secret", NULL, 30, &err);

  assert_that (p, is_null);
  assert_that (err, is_equal_to (GVM_OAUTH2_NEW_ERR_INVALID_TOKEN_URL));
}

Ensure (oauth2, get_token_returns_error_on_null_provider)
{
  gvm_oauth2_get_token_err_t err = GVM_OAUTH2_GET_TOKEN_ERR_OK;

  char *tok = gvm_oauth2_get_token (NULL, &err);

  assert_that (tok, is_null);
  assert_that (err, is_equal_to (GVM_OAUTH2_GET_TOKEN_ERR_NO_PROVIDER));
}

Ensure (oauth2, get_token_success_returns_c_string)
{
  int port = 18081;
  int rc = start_rust_test_server (
    200,
    "{\"access_token\":\"t1\",\"token_type\":\"bearer\",\"expires_in\":3600}",
    &port);

  assert_that (rc, is_equal_to (0));
  assert_that (port, is_greater_than (0));

  char url[256];
  create_token_url (url, sizeof (url), port);

  gvm_oauth2_new_err_t new_err = GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
  gvm_oauth2_token_provider_t p =
    gvm_oauth2_token_provider_new (url, "id", "secret", NULL, 30, &new_err);

  assert_that (p, is_not_null);
  assert_that (new_err, is_equal_to (GVM_OAUTH2_NEW_ERR_OK));

  gvm_oauth2_get_token_err_t tok_err = GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
  char *tok = gvm_oauth2_get_token (p, &tok_err);

  assert_that (tok_err, is_equal_to (GVM_OAUTH2_GET_TOKEN_ERR_OK));
  assert_that (tok, is_not_null);
  assert_that (tok, is_equal_to_string ("t1"));

  gvm_auth_str_free (tok);
  gvm_oauth2_token_provider_free (p);
  stop_rust_test_server ();
}

Ensure (oauth2, get_token_server_500_maps_to_request_failed)
{
  int port = 18081;
  int rc = start_rust_test_server (
    500, "{\"error\":\"server_error\",\"error_description\":\"err\"}", &port);

  assert_that (rc, is_equal_to (0));
  assert_that (port, is_greater_than (0));

  char url[256];
  create_token_url (url, sizeof (url), port);

  gvm_oauth2_new_err_t new_err = GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
  gvm_oauth2_token_provider_t p =
    gvm_oauth2_token_provider_new (url, "id", "secret", NULL, 30, &new_err);

  assert_that (p, is_not_null);
  assert_that (new_err, is_equal_to (GVM_OAUTH2_NEW_ERR_OK));

  gvm_oauth2_get_token_err_t tok_err = GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
  char *tok = gvm_oauth2_get_token (p, &tok_err);

  assert_that (tok, is_null);
  assert_that (tok_err, is_equal_to (GVM_OAUTH2_GET_TOKEN_ERR_REQUEST_FAILED));

  gvm_oauth2_token_provider_free (p);
  stop_rust_test_server ();
}

Ensure (oauth2, get_token_missing_expires_in_maps_to_missing_expires_in_err)
{
  int port = 18081;
  int rc = start_rust_test_server (
    200, "{\"access_token\":\"t1\",\"token_type\":\"bearer\"}", &port);

  assert_that (rc, is_equal_to (0));
  assert_that (port, is_greater_than (0));

  char url[256];
  create_token_url (url, sizeof (url), port);

  gvm_oauth2_new_err_t new_err = GVM_OAUTH2_NEW_ERR_INTERNAL_ERROR;
  gvm_oauth2_token_provider_t p =
    gvm_oauth2_token_provider_new (url, "id", "secret", NULL, 30, &new_err);

  assert_that (p, is_not_null);
  assert_that (new_err, is_equal_to (GVM_OAUTH2_NEW_ERR_OK));

  gvm_oauth2_get_token_err_t tok_err = GVM_OAUTH2_GET_TOKEN_ERR_INTERNAL_ERROR;
  char *tok = gvm_oauth2_get_token (p, &tok_err);

  assert_that (tok, is_null);
  assert_that (tok_err,
               is_equal_to (GVM_OAUTH2_GET_TOKEN_ERR_MISSING_EXPIRES_IN));

  gvm_oauth2_token_provider_free (p);
  stop_rust_test_server ();
}

/* Test suite */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();
  TestReporter *reporter = create_text_reporter ();

  add_test_with_context (suite, oauth2, new_sets_error_on_null_inputs);
  add_test_with_context (suite, oauth2, new_maps_invalid_token_url);
  add_test_with_context (suite, oauth2,
                         get_token_returns_error_on_null_provider);
  add_test_with_context (suite, oauth2, get_token_success_returns_c_string);
  add_test_with_context (suite, oauth2,
                         get_token_server_500_maps_to_request_failed);
  add_test_with_context (
    suite, oauth2, get_token_missing_expires_in_maps_to_missing_expires_in_err);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], reporter);
  else
    ret = run_test_suite (suite, reporter);

  destroy_reporter (reporter);
  destroy_test_suite (suite);
  return ret;
}
