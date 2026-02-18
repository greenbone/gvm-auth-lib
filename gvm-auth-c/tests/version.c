/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <cgreen/cgreen.h>
#include <gvm_auth.h>

Describe (version);

BeforeEach (version)
{
}
AfterEach (version)
{
}

Ensure (version, can_get_version)
{
  assert_that (GVM_AUTH_VERSION, is_not_null);
  assert_that (GVM_AUTH_VERSION, is_equal_to_string (TEST_GVM_AUTH_VERSION));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();
  TestReporter *reporter = create_text_reporter ();

  add_test_with_context (suite, version, can_get_version);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], reporter);
  else
    ret = run_test_suite (suite, reporter);

  destroy_reporter (reporter);
  destroy_test_suite (suite);

  return ret;
}
