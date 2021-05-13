/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>

#include "openssl/include/openssl/evp.h"
#include "unity.h"

#include "besu_native_ec.h"
#include "ec_sign_test_vectors.h"
#include "utils.h"

void p256_sign_should_create_valid_signatures(
    const EVP_MD *md, struct sign_test_vector test_vectors[],
    int test_vectors_len) {
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_value_len = 0;

  for (int i = 0; i < test_vectors_len; i++) {
    unsigned char *data_bin = hex_to_bin(test_vectors[i].data);
    unsigned char *private_key_bin = hex_to_bin(test_vectors[i].private_key);
    unsigned char *public_key_bin = hex_to_bin(test_vectors[i].public_key);

    if (EVP_Digest(data_bin, strlen(test_vectors[i].data) / 2, md_value,
                   &md_value_len, md, NULL) != 1) {
      TEST_FAIL_MESSAGE("Hashing not successful");
    }

    struct sign_result result_sign =
        p256_sign(md_value, md_value_len, private_key_bin, public_key_bin);

    TEST_ASSERT_EQUAL_STRING("", result_sign.error_message);

    struct verify_result result_verify =
        p256_verify(md_value, md_value_len, result_sign.signature_r,
                    result_sign.signature_s, public_key_bin);

    TEST_ASSERT_EQUAL_STRING("", result_verify.error_message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, result_verify.verified,
                                  "Signature verification not successful");

    struct key_recovery_result result_key_recovery =
        p256_key_recovery(md_value, md_value_len, result_sign.signature_r,
                          result_sign.signature_s, result_sign.signature_v);

    TEST_ASSERT_EQUAL_STRING("", result_key_recovery.error_message);
    TEST_ASSERT_EQUAL_STRING(test_vectors[i].public_key,
                             to_lower_case(result_key_recovery.public_key));

    free(data_bin);
    free(private_key_bin);
    free(public_key_bin);
  }
}

void p256_sign_should_create_valid_signatures_from_sha224_hashes(void) {
  const EVP_MD *md = EVP_sha224();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha224) / sizeof(sign_test_vectors_sha224[0]);

  p256_sign_should_create_valid_signatures(md, sign_test_vectors_sha224,
                                           test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

void p256_sign_should_create_valid_signatures_from_sha256_hashes(void) {
  const EVP_MD *md = EVP_sha256();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha256) / sizeof(sign_test_vectors_sha256[0]);

  p256_sign_should_create_valid_signatures(md, sign_test_vectors_sha256,
                                           test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

void p256_sign_should_create_valid_signatures_from_sha384_hashes(void) {
  const EVP_MD *md = EVP_sha384();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha384) / sizeof(sign_test_vectors_sha384[0]);

  p256_sign_should_create_valid_signatures(md, sign_test_vectors_sha384,
                                           test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

void p256_sign_should_create_valid_signatures_from_sha512_hashes(void) {
  const EVP_MD *md = EVP_sha512();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha512) / sizeof(sign_test_vectors_sha512[0]);

  p256_sign_should_create_valid_signatures(md, sign_test_vectors_sha512,
                                           test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(p256_sign_should_create_valid_signatures_from_sha224_hashes);
  RUN_TEST(p256_sign_should_create_valid_signatures_from_sha256_hashes);
  RUN_TEST(p256_sign_should_create_valid_signatures_from_sha384_hashes);
  RUN_TEST(p256_sign_should_create_valid_signatures_from_sha512_hashes);

  return UNITY_END();
}

void setUp(void) {}

void tearDown(void) {}