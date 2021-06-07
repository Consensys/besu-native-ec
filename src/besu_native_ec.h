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

/**
 * This header file includes all functions that are publicly exposed by
 * the besu-native-ec library
 */

struct key_recovery_result {
  // 131 bytes are needed for a P-521 public key
  char public_key[131];
  char error_message[256];
};

struct sign_result {
  // 66 bytes are needed for one half of a P-521 signature
  char signature_r[66];
  char signature_s[66];
  char signature_v;
  char error_message[256];
};

struct verify_result {
  int verified;
  char error_message[256];
};

struct key_recovery_result p256_key_recovery(const char data_hash[],
                                             const int data_hash_len,
                                             const char signature_r[],
                                             const char signature_s[],
                                             const int signature_v);

struct sign_result p256_sign(const char data_hash[], const int data_hash_length,
                             const char private_key_data[],
                             const char public_key_data[]);

struct verify_result p256_verify(const char data_hash[],
                                 const int data_hash_length,
                                 const char signature_r[],
                                 const char signature_s[],
                                 const char public_key_data[]);

#ifdef __cplusplus
extern
}
#endif
