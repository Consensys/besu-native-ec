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
#include "unity.h"

#include "utils.h"

void hex_to_bin_should_return_correct_byte_array(void) {
  unsigned char expected_array[] = {0x1f, 0xe4, 0x76};
  TEST_ASSERT_EQUAL_CHAR_ARRAY(expected_array, hex_to_bin("1fe476"), 3);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(hex_to_bin_should_return_correct_byte_array);

  return UNITY_END();
}

void setUp(void) {}

void tearDown(void) {}
