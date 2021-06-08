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

struct sign_result sign(const char data_hash[], const int data_hash_len,
                        const char private_key_data[], int private_key_len,
                        const char public_key_data[], int public_key_len,
                        const char *group_name, int curve_nid);

ECDSA_SIG *create_signature(EVP_PKEY *key, char *error_message,
                            const unsigned char *data_hash,
                            const size_t data_hash_length);

int signature_to_bin_values(const ECDSA_SIG *signature, char *error_message,
                            char **signature_r, char **signature_s,
                            const int signature_len);

int calculate_signature_v(struct sign_result *result, const char data_hash[],
                          const size_t data_hash_len, const char signature_r[],
                          const char signature_s[],
                          const char public_key_data[], uint8_t public_key_len,
                          uint8_t curve_byte_len, int curve_nid);

#ifdef __cplusplus
extern
}
#endif
