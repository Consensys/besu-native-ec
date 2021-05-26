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
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "openssl/include/openssl/err.h"

#include "utils.h"

void set_error_message(char *error_message, const char *message_prefix) {
  snprintf(error_message, 256, "%s: %s\n", message_prefix,
           ERR_error_string(ERR_get_error(), NULL));
}

unsigned char *hex_to_bin(const char *hex_string) {

  if (hex_string == NULL)
    return NULL;

  size_t slength = strlen(hex_string);
  if ((slength % 2) != 0) // must be even
    return NULL;

  size_t dlength = slength / 2;

  unsigned char *data = malloc(dlength);
  memset(data, 0, dlength);

  size_t index = 0;
  while (index < slength) {
    char c = hex_string[index];
    int value = 0;
    if (c >= '0' && c <= '9')
      value = (c - '0');
    else if (c >= 'A' && c <= 'F')
      value = (10 + (c - 'A'));
    else if (c >= 'a' && c <= 'f')
      value = (10 + (c - 'a'));
    else {
      free(data);
      return NULL;
    }

    data[(index / 2)] += value << (((index + 1) % 2) * 4);

    index++;
  }

  return data;
}

char *to_lower_case(char *s) {
  for (char *p = s; *p; p++) {
    *p = tolower(*p);
  }

  return s;
}