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
#include <stdlib.h>
#include <string.h>

#include "openssl/include/openssl/evp.h"
#include "unity.h"

#include "besu_native_ec.h"
#include "ec_sign_test_vectors.h"
#include "utils.h"

void p256_key_recovery_should_recover_correct_public_keys(
    const EVP_MD *md, struct sign_test_vector test_vectors[],
    int test_vectors_len) {
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_value_len = 0;

  for (int i = 0; i < test_vectors_len; i++) {
    unsigned char *data_bin = hex_to_bin(test_vectors[i].data);
    char *signature_r_bin = (char *)hex_to_bin(test_vectors[i].signature_r);
    char *signature_s_bin = (char *)hex_to_bin(test_vectors[i].signature_s);
    char *public_key_bin = (char *)hex_to_bin(test_vectors[i].public_key);

    if (EVP_Digest(data_bin, strlen(test_vectors[i].data) / 2, md_value,
                   &md_value_len, md, NULL) != 1) {
      TEST_FAIL_MESSAGE("Hashing not successful");
    }

    struct key_recovery_result result =
        p256_key_recovery((const char *)md_value, md_value_len, signature_r_bin,
                          signature_s_bin, test_vectors[i].signature_v);

    TEST_ASSERT_EQUAL_STRING("", result.error_message);
    TEST_ASSERT_EQUAL_CHAR_ARRAY(public_key_bin, result.public_key, 64);

    free(data_bin);
    free(signature_r_bin);
    free(signature_s_bin);
    free(public_key_bin);
  }
}

void p256_key_recovery_should_recover_correct_public_keys_from_sha224_hashes(
    void) {
  const EVP_MD *md = EVP_sha224();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha224) / sizeof(sign_test_vectors_sha224[0]);

  p256_key_recovery_should_recover_correct_public_keys(
      md, sign_test_vectors_sha224, test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

void p256_key_recovery_should_recover_correct_public_keys_from_sha256_hashes(
    void) {
  const EVP_MD *md = EVP_sha256();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha256) / sizeof(sign_test_vectors_sha256[0]);

  p256_key_recovery_should_recover_correct_public_keys(
      md, sign_test_vectors_sha256, test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

void p256_key_recovery_should_recover_correct_public_keys_from_sha384_hashes(
    void) {
  const EVP_MD *md = EVP_sha384();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha384) / sizeof(sign_test_vectors_sha384[0]);

  p256_key_recovery_should_recover_correct_public_keys(
      md, sign_test_vectors_sha384, test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

void p256_key_recovery_should_recover_correct_public_keys_from_sha512_hashes(
    void) {
  const EVP_MD *md = EVP_sha512();
  int test_vectors_len =
      sizeof(sign_test_vectors_sha512) / sizeof(sign_test_vectors_sha512[0]);

  p256_key_recovery_should_recover_correct_public_keys(
      md, sign_test_vectors_sha512, test_vectors_len);

  EVP_MD_free((EVP_MD *)md);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(
      p256_key_recovery_should_recover_correct_public_keys_from_sha224_hashes);
  RUN_TEST(
      p256_key_recovery_should_recover_correct_public_keys_from_sha256_hashes);
  RUN_TEST(
      p256_key_recovery_should_recover_correct_public_keys_from_sha384_hashes);
  RUN_TEST(
      p256_key_recovery_should_recover_correct_public_keys_from_sha512_hashes);

  return UNITY_END();
}

void setUp(void) {}

void tearDown(void) {}