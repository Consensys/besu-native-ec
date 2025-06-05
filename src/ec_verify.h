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
#include <stdbool.h>

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct verify_result verify(const char data_hash[], const int data_hash_length,
                            const char signature_r_hex[],
                            const char signature_s_hex[],
                            const char public_key_data[], int public_key_len,
                            const char *group_name, int curve_nid, bool allow_malleable_signature);

struct verify_result p256_verify_malleable_signature(const char data_hash[],
                                                 const int data_hash_length,
                                                 const char signature_r_hex[],
                                                 const char signature_s_hex[],
                                                 const char public_key_data[]);


int create_der_encoded_signature(unsigned char **der_encoded_signature,
                                 int *der_encoded_signature_len,
                                 char *error_message,
                                 const char signature_r_arr[],
                                 const char signature_s_arr[],
                                 int signature_arr_len);

int is_signature_canonicalized(const char signature_s_arr[],
                               const int signature_arr_len, const int curve_nid,
                               char *error_message);

#ifdef __cplusplus
extern
}
#endif
