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
#include "ec_verify_test_vectors.h"
#include "utils.h"

void p256_verify_should_verify_signatures_according_to_test_vectors(void) {
  int test_vectors_len = sizeof(test_vectors) / sizeof(test_vectors[0]);

  const EVP_MD *md_sha224 = EVP_sha224();
  const EVP_MD *md_sha256 = EVP_sha256();
  const EVP_MD *md_sha384 = EVP_sha384();
  const EVP_MD *md_sha512 = EVP_sha512();

  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_value_len = 0;
  const EVP_MD *md = NULL;

  for (int i = 0; i < test_vectors_len; i++) {
    switch (test_vectors[i].hash_function_id) {
    case SHA_224:
      md = md_sha224;
      break;
    case SHA_256:
      md = md_sha256;
      break;
    case SHA_384:
      md = md_sha384;
      break;
    case SHA_512:
      md = md_sha512;
      break;
    default:
      TEST_FAIL_MESSAGE("Unknown hash id");
    }

    unsigned char *data_bin = hex_to_bin(test_vectors[i].data);
    char *public_key_bin = (char *)hex_to_bin(test_vectors[i].public_key);
    char *signature_r_bin = (char *)hex_to_bin(test_vectors[i].signature_r);
    char *signature_s_bin = (char *)hex_to_bin(test_vectors[i].signature_s);

    if (EVP_Digest(data_bin, strlen(test_vectors[i].data) / 2, md_value,
                   &md_value_len, md, NULL) != 1) {
      TEST_FAIL_MESSAGE("Hashing not successful");
    }

    struct verify_result result =
        p256_verify((const char *)md_value, md_value_len, signature_r_bin,
                    signature_s_bin, (const char *)public_key_bin);

    TEST_ASSERT_EQUAL_INT(test_vectors[i].result, result.verified);

    free(data_bin);
    free(public_key_bin);
    free(signature_r_bin);
    free(signature_s_bin);
  }

  EVP_MD_free((EVP_MD *)md_sha224);
  EVP_MD_free((EVP_MD *)md_sha256);
  EVP_MD_free((EVP_MD *)md_sha384);
  EVP_MD_free((EVP_MD *)md_sha512);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(p256_verify_should_verify_signatures_according_to_test_vectors);

  return UNITY_END();
}

void setUp(void) {}

void tearDown(void) {}