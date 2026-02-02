/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Tests of the JWT C functions.
 */

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#include <gvm_auth_c_lib.h>
#include <test_data.h>

Describe (jwt);
BeforeEach (jwt)
{
}
AfterEach (jwt)
{
}

Ensure (jwt, can_generate_valid_token)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  int ret;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF");
  assert_that (enc_secret, is_not_null);
  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF");
  assert_that (dec_secret, is_not_null);
  
  token = gvm_jwt_generate_token (enc_secret, "testuser", 100);
  
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  ret = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (ret, is_equal_to (0));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, can_generate_valid_token_from_ecdsa_pem)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  int ret;

  enc_secret = gvm_jwt_new_ec_pem_encode_secret (TEST_ECDSA_PRIVATE_PEM);
  assert_that (enc_secret, is_not_null);
  dec_secret = gvm_jwt_new_ec_pem_decode_secret (TEST_ECDSA_PUBLIC_PEM);
  assert_that (dec_secret, is_not_null);
  
  token = gvm_jwt_generate_token (enc_secret, "testuser", 100);
  
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  ret = gvm_jwt_validate_token (dec_secret, token, "testuser");
  assert_that (ret, is_equal_to (0));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, can_generate_valid_token_from_rsa_pem)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  int ret;

  enc_secret = gvm_jwt_new_rsa_pem_encode_secret (TEST_RSA_PRIVATE_PEM);
  assert_that (enc_secret, is_not_null);
  dec_secret = gvm_jwt_new_rsa_pem_decode_secret (TEST_RSA_PUBLIC_PEM);
  assert_that (dec_secret, is_not_null);
  
  token = gvm_jwt_generate_token (enc_secret, "testuser", 100);
  
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  ret = gvm_jwt_validate_token (dec_secret, token, "testuser");
  assert_that (ret, is_equal_to (0));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, can_validate_subject)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  int ret;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF");
  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF");
  
  token = gvm_jwt_generate_token (enc_secret, "testuser", 100);

  ret = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (ret, is_equal_to (0));

  ret = gvm_jwt_validate_token (dec_secret, token, "testuser");
  assert_that (ret, is_equal_to (0));

  ret = gvm_jwt_validate_token (dec_secret, token, "invalid");
  assert_that (ret, is_equal_to (2));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, rejects_expired_token)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  int ret;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF");
  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF");
  
  token = gvm_jwt_generate_token (enc_secret, "testuser", -100);
  
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  ret = gvm_jwt_validate_token (dec_secret, token, "testuser");
  assert_that (ret, is_equal_to (1));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}


/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;
  TestReporter *reporter;

  suite = create_test_suite ();
  reporter = create_text_reporter ();

  add_test_with_context (suite, jwt, can_generate_valid_token);
  add_test_with_context (suite, jwt, can_generate_valid_token_from_ecdsa_pem);
  add_test_with_context (suite, jwt, can_generate_valid_token_from_rsa_pem);
  add_test_with_context (suite, jwt, can_validate_subject);
  add_test_with_context (suite, jwt, rejects_expired_token);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], reporter);
  else
    ret = run_test_suite (suite, reporter);

  destroy_reporter (reporter);
  destroy_test_suite (suite);

  return ret;
}
