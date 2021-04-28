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

int create_key(EVP_PKEY **key, struct verify_result *result,
               const unsigned char public_key_data[]);

int create_signature_DER(unsigned char **signature_der, int *signature_der_len,
                         struct verify_result *result,
                         const char *signature_r_hex,
                         const char *signature_s_hex);

void set_error_message(char *buffer, const char *message_prefix);

#ifdef __cplusplus
extern
}
#endif
