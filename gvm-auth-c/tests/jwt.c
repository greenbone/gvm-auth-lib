/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 * @brief Tests of the JWT C functions.
 */

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <gvm_auth.h>
#include <test_data.h>
#include <time.h>

Describe (jwt);
BeforeEach (jwt)
{
}
AfterEach (jwt)
{
}

Ensure (jwt, can_get_new_secret_error_strings)
{
  assert_that (gvm_jwt_new_secret_strerror (
                  GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR),
               is_equal_to_string ("internal error"));

  assert_that (gvm_jwt_new_secret_strerror (GVM_JWT_NEW_SECRET_ERR_OK),
               is_equal_to_string ("ok"));

  assert_that (gvm_jwt_new_secret_strerror (GVM_JWT_NEW_SECRET_ERR_NO_DATA),
               is_equal_to_string ("no secret data given"));

  assert_that (gvm_jwt_new_secret_strerror (
                  GVM_JWT_NEW_SECRET_ERR_STRING_CONVERSION_FAILED),
               is_equal_to_string ("data could not be converted to a string"));

  assert_that (gvm_jwt_new_secret_strerror (
                  GVM_JWT_NEW_SECRET_ERR_INVALID_EC_PEM),
               is_equal_to_string ("data is not valid ECDSA PEM"));

  assert_that (gvm_jwt_new_secret_strerror (
                  GVM_JWT_NEW_SECRET_ERR_INVALID_RSA_PEM),
               is_equal_to_string ("data is not valid RSA PEM key"));


  assert_that (gvm_jwt_new_secret_strerror (-2),
               is_equal_to_string ("unknown error"));

  assert_that (gvm_jwt_new_secret_strerror (5),
               is_equal_to_string ("unknown error"));

  assert_that (gvm_jwt_new_secret_strerror (123),
               is_equal_to_string ("unknown error"));
}

Ensure (jwt, can_get_generate_error_strings)
{
  assert_that (gvm_jwt_generate_token_strerror (
                  GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR),
               is_equal_to_string ("internal error"));

  assert_that (gvm_jwt_generate_token_strerror (GVM_JWT_GENERATE_TOKEN_ERR_OK),
               is_equal_to_string ("ok"));

  assert_that (gvm_jwt_generate_token_strerror (
                  GVM_JWT_GENERATE_TOKEN_ERR_NO_SECRET),
               is_equal_to_string ("no secret given"));

  assert_that (gvm_jwt_generate_token_strerror (
                  GVM_JWT_GENERATE_TOKEN_ERR_INVALID_USER_ID),
               is_equal_to_string ("username could not be converted to a string"));

  assert_that (gvm_jwt_generate_token_strerror (
                  GVM_JWT_GENERATE_TOKEN_ERR_GENERATE_FAILED),
               is_equal_to_string ("failed to generate token"));

  assert_that (gvm_jwt_generate_token_strerror (-2),
               is_equal_to_string ("unknown error"));

  assert_that (gvm_jwt_generate_token_strerror (4),
               is_equal_to_string ("unknown error"));

  assert_that (gvm_jwt_generate_token_strerror (123),
               is_equal_to_string ("unknown error"));
}

Ensure (jwt, can_get_validate_error_strings)
{
  assert_that (gvm_jwt_validate_token_strerror (
                  GVM_JWT_VALIDATE_TOKEN_ERR_INTERNAL_ERROR),
               is_equal_to_string ("internal error"));

  assert_that (gvm_jwt_validate_token_strerror (GVM_JWT_VALIDATE_TOKEN_ERR_OK),
               is_equal_to_string ("ok"));

  assert_that (gvm_jwt_validate_token_strerror (
                  GVM_JWT_VALIDATE_TOKEN_ERR_NO_SECRET),
               is_equal_to_string ("no secret given"));

  assert_that (gvm_jwt_validate_token_strerror (
                  GVM_JWT_VALIDATE_TOKEN_ERR_VALIDATION_FAILED),
               is_equal_to_string ("failed to validate token"));

  assert_that (gvm_jwt_validate_token_strerror (
                  GVM_JWT_VALIDATE_TOKEN_MALFORMED_CLAIMS),
               is_equal_to_string ("token claims do not match expected structure"));

  assert_that (gvm_jwt_validate_token_strerror (-2),
               is_equal_to_string ("unknown error"));

  assert_that (gvm_jwt_validate_token_strerror (6),
               is_equal_to_string ("unknown error"));

  assert_that (gvm_jwt_validate_token_strerror (123),
               is_equal_to_string ("unknown error"));
}

Ensure (jwt, can_generate_valid_token)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  gvm_jwt_new_secret_err_t new_secret_err;
  char *token;
  gvm_jwt_generate_token_err_t generate_token_err;
  gvm_jwt_validate_token_err_t validate_token_err;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", &new_secret_err);
  assert_that (new_secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
  assert_that (enc_secret, is_not_null);

  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF", &new_secret_err);
  assert_that (new_secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
  assert_that (dec_secret, is_not_null);

  generate_token_err = GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;
  token =
    gvm_jwt_generate_token (enc_secret, "testuser", 100, &generate_token_err);
  assert_that (generate_token_err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  validate_token_err = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (validate_token_err, is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_OK));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, can_generate_valid_token_from_ecdsa_pem)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  gvm_jwt_new_secret_err_t new_secret_err;
  char *token;
  gvm_jwt_generate_token_err_t generate_token_err;
  gvm_jwt_validate_token_err_t validate_token_err;

  new_secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;
  enc_secret =
    gvm_jwt_new_ec_pem_encode_secret (TEST_ECDSA_PRIVATE_PEM, &new_secret_err);
  assert_that (new_secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
  assert_that (enc_secret, is_not_null);

  new_secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;
  dec_secret =
    gvm_jwt_new_ec_pem_decode_secret (TEST_ECDSA_PUBLIC_PEM, &new_secret_err);
  assert_that (new_secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
  assert_that (dec_secret, is_not_null);

  generate_token_err = GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;
  token =
    gvm_jwt_generate_token (enc_secret, "testuser", 100, &generate_token_err);
  assert_that (generate_token_err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  validate_token_err = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (validate_token_err, is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_OK));
  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, can_generate_valid_token_from_rsa_pem)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  gvm_jwt_new_secret_err_t new_secret_err;
  char *token;
  gvm_jwt_generate_token_err_t generate_token_err;
  gvm_jwt_validate_token_err_t validate_token_err;

  new_secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;
  enc_secret =
    gvm_jwt_new_rsa_pem_encode_secret (TEST_RSA_PRIVATE_PEM, &new_secret_err);
  assert_that (new_secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
  assert_that (enc_secret, is_not_null);

  new_secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;
  dec_secret =
    gvm_jwt_new_rsa_pem_decode_secret (TEST_RSA_PUBLIC_PEM, &new_secret_err);
  assert_that (new_secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
  assert_that (dec_secret, is_not_null);

  generate_token_err = GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;
  token =
    gvm_jwt_generate_token (enc_secret, "testuser", 100, &generate_token_err);

  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));
  assert_that (generate_token_err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));

  validate_token_err = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (validate_token_err, is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_OK));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, can_get_token_claims)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  gvm_jwt_validate_token_err_t validate_token_err;
  gvm_jwt_claims_t claims;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", NULL);
  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF", NULL);

  token = gvm_jwt_generate_token (enc_secret, "testuser", 100, NULL);

  validate_token_err = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (validate_token_err, is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_OK));

  validate_token_err = gvm_jwt_validate_token (dec_secret, token, &claims);
  assert_that (validate_token_err, is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_OK));

  time_t now = time (NULL);
  uint64_t iat = gvm_jwt_claims_get_iat (claims);
  uint64_t exp = gvm_jwt_claims_get_exp (claims);
  const char *sub = gvm_jwt_claims_get_sub (claims);

  assert_that (iat, is_greater_than (now - 10));
  assert_that (exp, is_greater_than (now - 10));
  assert_that (exp - iat, is_equal_to (100));
  assert_that (sub, is_equal_to_string ("testuser"));

  gvm_jwt_claims_free (claims);
  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, rejects_expired_token)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  gvm_jwt_generate_token_err_t generate_token_err;
  gvm_jwt_validate_token_err_t validate_token_err;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", NULL);
  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF", NULL);

  generate_token_err = GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;
  token =
    gvm_jwt_generate_token (enc_secret, "testuser", -100, &generate_token_err);
  assert_that (generate_token_err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  validate_token_err = gvm_jwt_validate_token (dec_secret, token, NULL);
  assert_that (validate_token_err,
               is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_VALIDATION_FAILED));

  gvm_jwt_encode_secret_free (enc_secret);
  gvm_jwt_decode_secret_free (dec_secret);
  gvm_auth_str_free (token);
}

Ensure (jwt, rejects_null_secret_or_token)
{
  gvm_jwt_encode_secret_t enc_secret;
  gvm_jwt_decode_secret_t dec_secret;
  char *token;
  gvm_jwt_generate_token_err_t generate_token_err;
  gvm_jwt_validate_token_err_t validate_token_err;

  enc_secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", NULL);
  dec_secret = gvm_jwt_new_shared_decode_secret ("ABCDEF", NULL);

  generate_token_err = GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;
  token =
    gvm_jwt_generate_token (enc_secret, "testuser", -100, &generate_token_err);
  assert_that (generate_token_err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
  assert_that (token, is_not_null);
  assert_that (token, is_not_equal_to_string (""));

  validate_token_err = gvm_jwt_validate_token (NULL, token, NULL);
  assert_that (validate_token_err,
               is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_NO_SECRET));

  validate_token_err = gvm_jwt_validate_token (dec_secret, NULL, NULL);
  assert_that (validate_token_err,
               is_equal_to (GVM_JWT_VALIDATE_TOKEN_ERR_NO_TOKEN));

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

  add_test_with_context (suite, jwt, can_get_new_secret_error_strings);
  add_test_with_context (suite, jwt, can_get_generate_error_strings);
  add_test_with_context (suite, jwt, can_get_validate_error_strings);
  add_test_with_context (suite, jwt, can_generate_valid_token);
  add_test_with_context (suite, jwt, can_generate_valid_token_from_ecdsa_pem);
  add_test_with_context (suite, jwt, can_generate_valid_token_from_rsa_pem);
  add_test_with_context (suite, jwt, can_get_token_claims);
  add_test_with_context (suite, jwt, rejects_expired_token);
  add_test_with_context (suite, jwt, rejects_null_secret_or_token);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], reporter);
  else
    ret = run_test_suite (suite, reporter);

  destroy_reporter (reporter);
  destroy_test_suite (suite);

  return ret;
}
