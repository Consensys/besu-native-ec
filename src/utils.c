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
#include <stdio.h>
#include <string.h>

#include "openssl/include/openssl/err.h"

#include "utils.h"

void set_error_message(char *error_message, const char *message_prefix) {
  snprintf(error_message, 256, "%s: %s\n", message_prefix,
           ERR_error_string(ERR_get_error(), NULL));
}

unsigned char *hex_to_bin(const char *hex_string) {
  int hex_string_len = strlen((char *)hex_string);
  unsigned char *byte_array =
      malloc(hex_string_len / 2 * (sizeof(unsigned char)));

  for (int i = 0; i < (hex_string_len / 2); i++) {
    sscanf(hex_string + 2 * i, "%02x", (unsigned int *)&byte_array[i]);
  }

  return byte_array;
}