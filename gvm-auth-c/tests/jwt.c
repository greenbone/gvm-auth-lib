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
#include <string.h>
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

  assert_that (
    gvm_jwt_generate_token_strerror (GVM_JWT_GENERATE_TOKEN_ERR_NO_PAYLOAD),
    is_equal_to_string ("no payload given"));

  assert_that (
    gvm_jwt_generate_token_strerror (
      GVM_JWT_GENERATE_TOKEN_ERR_INVALID_PAYLOAD),
    is_equal_to_string ("payload could not be converted to a UTF-8 string"));

  assert_that (gvm_jwt_generate_token_strerror (6),
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

Ensure (jwt, can_generate_payload_tokens_from_agent_control_vectors)
{
  const struct
  {
    const char *secret;
    const char *payload;
    const char *token;
  } vectors[] = {
    {"0123456789abcdef0123456789abcdef",
     "{\"v\":1,\"iat\":1755158400,\"exp\":1755159000,\"nonce\":"
     "\"kf3B9zR2xY7pQ4mW8sT1Vg\"}",
     "eyJ2IjoxLCJpYXQiOjE3NTUxNTg0MDAsImV4cCI6MTc1NTE1OTAwMCwibm9uY2UiOiJrZjNCO"
     "XpSMnhZN3BRNG1XOHNUMVZnIn0.fXt4Ig3MjwukZ107eO3vyLxpp9YGs7UBiEKcORa5_t4"},
    {"0123456789abcdef0123456789abcdef",
     "{\"nonce\":\"Zm9vYmFyMTIzNDU2Nzg5MA\",\"exp\":1755159000,\"iat\":"
     "1755158400,\"v\":1}",
     "eyJub25jZSI6IlptOXZZbUZ5TVRJek5EVTJOemc1TUEiLCJleHAiOjE3NTUxNTkwMDAsImlhd"
     "CI6MTc1NTE1ODQwMCwidiI6MX0.nsUR7tM5RmL2mTBi-yTOBehtxQQHLObEmiraXUqO6dw"},
    {"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
     "{\"v\":1,\"iat\":1755158400,\"exp\":1755159000,\"nonce\":"
     "\"kf3B9zR2xY7pQ4mW8sT1Vg\"}",
     "eyJ2IjoxLCJpYXQiOjE3NTUxNTg0MDAsImV4cCI6MTc1NTE1OTAwMCwibm9uY2UiOiJrZjNCO"
     "XpSMnhZN3BRNG1XOHNUMVZnIn0.raxzRNLjAu9FiBA1Mcdh1TfgRmmH9KbTKcM3Xf9CUMM"},
  };

  for (size_t i = 0; i < sizeof (vectors) / sizeof (vectors[0]); i++)
    {
      gvm_jwt_new_secret_err_t secret_err;
      gvm_jwt_generate_token_err_t err;
      gvm_jwt_encode_secret_t secret;
      char *token;

      secret =
        gvm_jwt_new_shared_encode_secret (vectors[i].secret, &secret_err);
      assert_that (secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
      assert_that (secret, is_not_null);

      err = GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;
      token =
        gvm_jwt_generate_token_with_payload (secret, vectors[i].payload, &err);
      assert_that (err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
      assert_that (token, is_not_null);
      assert_that (token, is_equal_to_string (vectors[i].token));

      gvm_auth_str_free (token);
      gvm_jwt_encode_secret_free (secret);
    }
}

Ensure (jwt, can_generate_payload_tokens_from_all_secret_types)
{
  const struct
  {
    gvm_jwt_secret_type_t type;
    const char *data;
    size_t signature_length;
  } secrets[] = {
    {GVM_JWT_SECRET_TYPE_SHARED, "0123456789abcdef0123456789abcdef", 43},
    {GVM_JWT_SECRET_TYPE_RSA_PEM, TEST_RSA_PRIVATE_PEM, 342},
    {GVM_JWT_SECRET_TYPE_EC_PEM, TEST_ECDSA_PRIVATE_PEM, 86},
  };
  const char *prefix = "eyJjdXN0b20iOiJ2YWx1ZSJ9.";
  const char *alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  for (size_t i = 0; i < sizeof (secrets) / sizeof (secrets[0]); i++)
    {
      gvm_jwt_new_secret_err_t secret_err;
      gvm_jwt_generate_token_err_t err;
      gvm_jwt_encode_secret_t secret;
      char *token;
      const char *signature;

      secret = gvm_jwt_new_encode_secret (secrets[i].type, secrets[i].data,
                                          &secret_err);
      assert_that (secret_err, is_equal_to (GVM_JWT_NEW_SECRET_ERR_OK));
      assert_that (secret, is_not_null);

      token = gvm_jwt_generate_token_with_payload (
        secret, "{\"custom\":\"value\"}", &err);
      assert_that (err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
      assert_that (token, is_not_null);
      assert_that (strncmp (token, prefix, strlen (prefix)), is_equal_to (0));

      signature = strchr (token, '.');
      assert_that (signature, is_not_null);
      signature++;
      assert_that (strlen (signature),
                   is_equal_to (secrets[i].signature_length));
      assert_that (strspn (signature, alphabet),
                   is_equal_to (strlen (signature)));

      gvm_auth_str_free (token);
      gvm_jwt_encode_secret_free (secret);
    }
}

Ensure (jwt, preserves_custom_payload_bytes)
{
  gvm_jwt_encode_secret_t secret;
  gvm_jwt_generate_token_err_t err;
  char *token;
  const char *payload = "{\n  \"custom\": {\"name\": \"München\", \"roles\": "
                        "[\"agent\"]},\n  \"enabled\": true\n}";
  const char *expected =
    "ewogICJjdXN0b20iOiB7Im5hbWUiOiAiTcO8bmNoZW4iLCAicm9sZXMiOiBbImFnZW50Il19LA"
    "ogICJlbmFibGVkIjogdHJ1ZQp9.jrQMKDDqgaof5uLd13iqDQ_vayUwu2VcQuATuxxTjio";

  secret =
    gvm_jwt_new_shared_encode_secret ("0123456789abcdef0123456789abcdef", NULL);
  assert_that (secret, is_not_null);

  token = gvm_jwt_generate_token_with_payload (secret, payload, &err);
  assert_that (err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_OK));
  assert_that (token, is_not_null);
  assert_that (token, is_equal_to_string (expected));

  gvm_auth_str_free (token);
  gvm_jwt_encode_secret_free (secret);
}

Ensure (jwt, can_generate_payload_token_without_error_output)
{
  gvm_jwt_encode_secret_t secret;
  char *token;

  secret =
    gvm_jwt_new_shared_encode_secret ("0123456789abcdef0123456789abcdef", NULL);
  assert_that (secret, is_not_null);

  token = gvm_jwt_generate_token_with_payload (secret, "{\"custom\":\"value\"}",
                                               NULL);
  assert_that (token, is_not_null);
  assert_that (
    token,
    is_equal_to_string (
      "eyJjdXN0b20iOiJ2YWx1ZSJ9.cOo3qw8pllorSjbNT-622pheYdSabOhpYPGj5B038B8"));

  gvm_auth_str_free (token);
  gvm_jwt_encode_secret_free (secret);
}

Ensure (jwt, rejects_null_secret_for_payload_token)
{
  gvm_jwt_generate_token_err_t err = GVM_JWT_GENERATE_TOKEN_ERR_OK;
  char *token;

  token = gvm_jwt_generate_token_with_payload (NULL, "{}", &err);
  assert_that (token, is_null);
  assert_that (err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_NO_SECRET));
}

Ensure (jwt, rejects_null_payload_for_payload_token)
{
  gvm_jwt_encode_secret_t secret;
  gvm_jwt_generate_token_err_t err = GVM_JWT_GENERATE_TOKEN_ERR_OK;
  char *token;

  secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", NULL);
  assert_that (secret, is_not_null);

  token = gvm_jwt_generate_token_with_payload (secret, NULL, &err);
  assert_that (token, is_null);
  assert_that (err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_NO_PAYLOAD));

  gvm_jwt_encode_secret_free (secret);
}

Ensure (jwt, rejects_non_utf8_payload)
{
  gvm_jwt_encode_secret_t secret;
  gvm_jwt_generate_token_err_t err = GVM_JWT_GENERATE_TOKEN_ERR_OK;
  const char payload[] = {(char) 0xff, '\0'};
  char *token;

  secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", NULL);
  assert_that (secret, is_not_null);

  token = gvm_jwt_generate_token_with_payload (secret, payload, &err);
  assert_that (token, is_null);
  assert_that (err, is_equal_to (GVM_JWT_GENERATE_TOKEN_ERR_INVALID_PAYLOAD));

  gvm_jwt_encode_secret_free (secret);
}

Ensure (jwt, handles_payload_errors_without_error_output)
{
  gvm_jwt_encode_secret_t secret;
  const char payload[] = {(char) 0xff, '\0'};
  char *token;

  secret = gvm_jwt_new_shared_encode_secret ("ABCDEF", NULL);
  assert_that (secret, is_not_null);

  token = gvm_jwt_generate_token_with_payload (NULL, "{}", NULL);
  assert_that (token, is_null);
  token = gvm_jwt_generate_token_with_payload (secret, NULL, NULL);
  assert_that (token, is_null);
  token = gvm_jwt_generate_token_with_payload (secret, payload, NULL);
  assert_that (token, is_null);

  gvm_jwt_encode_secret_free (secret);
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

  add_test_with_context (
    suite, jwt, can_generate_payload_tokens_from_agent_control_vectors);
  add_test_with_context (suite, jwt,
                         can_generate_payload_tokens_from_all_secret_types);
  add_test_with_context (suite, jwt, preserves_custom_payload_bytes);
  add_test_with_context (suite, jwt,
                         can_generate_payload_token_without_error_output);
  add_test_with_context (suite, jwt, rejects_null_secret_for_payload_token);
  add_test_with_context (suite, jwt, rejects_null_payload_for_payload_token);
  add_test_with_context (suite, jwt, rejects_non_utf8_payload);
  add_test_with_context (suite, jwt,
                         handles_payload_errors_without_error_output);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], reporter);
  else
    ret = run_test_suite (suite, reporter);

  destroy_reporter (reporter);
  destroy_test_suite (suite);

  return ret;
}
