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
#include "openssl/include/openssl/evp.h"
#include "openssl/include/openssl/param_build.h"

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int create_key_pair(EVP_PKEY **key, char *error_message,
                    const unsigned char private_key_data[],
                    uint8_t private_key_len,
                    const unsigned char public_key_data[],
                    uint8_t public_key_len, const char *group_name);

int create_public_key(EVP_PKEY **key, char *error_message,
                      const unsigned char public_key_data[],
                      uint8_t public_key_len, const char *group_name);

int create_key(EVP_PKEY **key, char *error_message, const char *group_name,
               OSSL_PARAM_BLD *param_bld);

OSSL_PARAM_BLD *generate_public_key_param(const unsigned char public_key_data[],
                                          uint8_t public_key_len,
                                          unsigned char *public_key_buffer);

#ifdef __cplusplus
extern
}
#endif
