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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct key_recovery_result {
  // 263 = 262 bytes are needed for a P-521 public key + 1 byte for the null
  // byte at the end
  char public_key[263];
  char error_message[256];
};

struct key_recovery_result p256_key_recovery(const unsigned char *data_hash,
                                             const size_t data_hash_len,
                                             const char *signature_r_hex,
                                             const char *signature_s_hex,
                                             unsigned int signature_v);

struct key_recovery_result key_recovery(const unsigned char *data_hash,
                                        size_t data_hash_len,
                                        const char *signature_r_hex,
                                        const char *signature_s_hex,
                                        unsigned int signature_v, int curve_nid,
                                        unsigned int curve_byte_length);

#ifdef __cplusplus
extern
}
#endif
