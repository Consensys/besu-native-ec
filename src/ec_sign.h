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
#include <stdint.h>
#include <stdlib.h>

#include "openssl/include/openssl/ecdsa.h"

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct sign_result {
  // 263 = 262 bytes are needed for a P-521 signature + 1 byte for the null byte
  // at the end
  char signature_r[263];
  char signature_s[263];
  int signature_v;
  char error_message[256];
};

struct sign_result p256_sign(const unsigned char *data_hash,
                             const size_t data_hash_length,
                             const unsigned char private_key_data[],
                             const unsigned char public_key_data[]);

struct sign_result
sign(const unsigned char *data_hash, const size_t data_hash_len,
     const unsigned char private_key_data[], uint8_t private_key_len,
     const unsigned char public_key_data[], uint8_t public_key_len,
     const char *group_name, int curve_nid);

ECDSA_SIG *create_signature(EVP_PKEY *key, char *error_message,
                            const unsigned char *data_hash,
                            const size_t data_hash_length);

int signature_to_hex_values(const ECDSA_SIG *signature, char *error_message,
                            char **signature_r, char **signature_s);

int calculate_signature_v(struct sign_result *result,
                          const unsigned char *data_hash,
                          const size_t data_hash_len, const char *signature_r,
                          const char *signature_s,
                          const unsigned char public_key_data[],
                          uint8_t public_key_len, uint8_t private_key_len,
                          int curve_nid);

#ifdef __cplusplus
extern
}
#endif
