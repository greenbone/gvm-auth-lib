#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

#
# Script to generate a C header file containing test data
#

file_map = {
  "TEST_ECDSA_PRIVATE_PEM": "ecdsa-private.pem",
  "TEST_ECDSA_PUBLIC_PEM": "ecdsa-public.pem",
  "TEST_RSA_PRIVATE_PEM": "rsa-private.pem",
  "TEST_RSA_PUBLIC_PEM": "rsa-public.pem",
}

print (
"""/*
 * This file has been automatically generated with generate-data-header.py
 *
 * It contains data for testing the gvm_auth_lib C library
 */
""")

for var_name in file_map:
  file_name = file_map[var_name]
  
  with open(file_name) as f:
    lines = f.readlines()
    
    print ("// From", file_name)
    print ("#define", var_name, "\\")
    for i in range(len(lines)):
      parts = [
        '"',
        lines[i].encode("unicode_escape").decode(),
        '"',
        ' \\' if i < len(lines) - 1 else ''
      ]
      print ("".join(parts))
    print ()
