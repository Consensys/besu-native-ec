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

#include "openssl/include/openssl/evp.h"

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct verify_result {
  int verified;
  char error_message[256];
};

struct verify_result p256_verify(const unsigned char *data_hash,
                                 const size_t data_hash_length,
                                 const char *signature_r,
                                 const char *signature_s,
                                 const unsigned char public_key_data[]);

struct verify_result verify(const unsigned char *data_hash,
                            const size_t data_hash_length,
                            const char *signature_r_hex,
                            const char *signature_s_hex,
                            const unsigned char public_key_data[],
                            const char *group_name, uint8_t public_key_len);

int create_key(EVP_PKEY **key, char *error_message,
               const unsigned char public_key_data[], const char *group_name,
               uint8_t public_key_len);

int create_der_encoded_signature(unsigned char **der_encoded_signature,
                                 int *der_encoded_signature_len,
                                 char *error_message,
                                 const char *signature_r_hex,
                                 const char *signature_s_hex);

void set_error_message(char *buffer, const char *message_prefix);

#ifdef __cplusplus
extern
}
#endif
