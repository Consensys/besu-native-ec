#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_signature.h"
#include "unity.h"

unsigned char *hex_to_bin(const char *hex_string) {
  int hex_string_len = strlen((char *)hex_string);
  unsigned char *byte_array =
      malloc(hex_string_len / 2 * (sizeof(unsigned char)));

  for (int i = 0; i < (hex_string_len / 2); i++) {
    sscanf(hex_string + 2 * i, "%02x", (unsigned int *)&byte_array[i]);
  }

  return byte_array;
}

void test_hex_to_bin_should_return_correct_byte_array(void) {
  unsigned char expected_array[] = {0x1f, 0xe4, 0x76};
  TEST_ASSERT_EQUAL_CHAR_ARRAY(expected_array, hex_to_bin("1fe476"), 3);
}

void test_p256_verify_should_return_true(void) {
  const char public_key[] =
      "aef250d166bb62a72667b9470f84d597b4f95fef172ddec7f606df2ba2ba948544ecf6b4"
      "e2f492fd2e4eb23266db4cf3bccbb38a75aa2030a42828f65ed63fff";
  const char data_hash[] =
      "9340487ba7c7964392ba590f171445e41e611186e6e610b613bb9bac18ee491e";
  const char signature_r[] =
      "6c3dbf504a4f1a41a21a43d73b35012bd6981f733452fbb97c693c723291ae0b";
  const char signature_s[] =
      "7beb6cefface21424c0efbd129426d7e47f34d02ccfc6ffcf9c30b29bcd4bec2";

  struct verify_result result =
      p256_verify(hex_to_bin(data_hash), 32, signature_r, signature_s,
                  hex_to_bin(public_key));

  TEST_ASSERT_EQUAL_STRING("", result.error_message);
  TEST_ASSERT_EQUAL_INT(1, result.verified);
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_hex_to_bin_should_return_correct_byte_array);
  RUN_TEST(test_p256_verify_should_return_true);

  return UNITY_END();
}

void setUp(void) {}

void tearDown(void) {}