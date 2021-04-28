#include <stdio.h>
#include <string.h>

#include "openssl/include/openssl/ec.h"
#include "openssl/include/openssl/err.h"
#include "openssl/include/openssl/param_build.h"

#include "crypto_signature.h"

static const uint8_t P256_PUBLIC_KEY_LENGTH = 64;
static const uint8_t P256_SIGNATURE_LENGTH = 64;

const int8_t SUCCESS = 1;
const int8_t FAILURE = 0;
const int8_t GENERIC_ERROR = -1;

struct verify_result p256_verify(const unsigned char *data_hash,
                                 const size_t data_hash_length,
                                 const char *signature_r_hex,
                                 const char *signature_s_hex,
                                 const unsigned char public_key_data[]) {
  struct verify_result result = {.verified = GENERIC_ERROR,
                                 .error_message = {0}};

  EVP_PKEY *key = NULL;
  if (create_key(&key, &result, public_key_data) != SUCCESS) {
    goto end;
  }

  unsigned char *signature_der = NULL;
  int signature_der_len = 0;
  if (create_signature_DER(&signature_der, &signature_der_len, &result,
                           signature_r_hex, signature_s_hex) != SUCCESS) {
    goto end;
  }

  EVP_PKEY_CTX *verify_context = NULL;
  if ((verify_context = EVP_PKEY_CTX_new(key, NULL)) == NULL) {
    set_error_message(result.error_message,
                      "Could not create a context for verifying: ");
    goto end;
  }

  if (EVP_PKEY_verify_init(verify_context) != SUCCESS) {
    set_error_message(result.error_message,
                      "Could not initialize a context for verifying: ");
    goto end;
  }

  //  if (EVP_PKEY_CTX_set_signature_md(verify_context, EVP_sha256()) !=
  //  SUCCESS) {
  //    set_error_message(
  //        result.error_message,
  //        "Could not set hashing algorithm for verifying context: ");
  //    goto end;
  //  }

  // verify signature: 1 = successfully verified, 0 = not successfully verified,
  // < 0 = error
  result.verified =
      EVP_PKEY_verify(verify_context, signature_der, P256_SIGNATURE_LENGTH,
                      data_hash, data_hash_length);

  if (result.verified == 0) {
    snprintf(result.error_message, 256, "Signature not valid");
  } else if (result.verified < 0) {
    set_error_message(result.error_message,
                      "Error while verifying signature: ");
  }

end:
  OPENSSL_free(signature_der);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(verify_context);

  return result;
}

int create_key(EVP_PKEY **key, struct verify_result *result,
               const unsigned char public_key_data[]) {
  const char *P256_GROUP_NAME = "prime256v1";

  int ret = FAILURE;
  EVP_PKEY_CTX *key_context = NULL;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *params = NULL;

  unsigned char public_key_uncompressed[P256_PUBLIC_KEY_LENGTH + 1];
  public_key_uncompressed[0] = POINT_CONVERSION_UNCOMPRESSED;
  memcpy((void *)(public_key_uncompressed + 1), public_key_data,
         P256_PUBLIC_KEY_LENGTH);

  param_bld = OSSL_PARAM_BLD_new();
  OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", P256_GROUP_NAME, 0);
  OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", public_key_uncompressed,
                                   sizeof(public_key_uncompressed));

  if ((params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
    set_error_message(result->error_message,
                      "Could not create parameters for key operation: ");
    goto create_key_end;
  }

  if ((key_context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) {
    set_error_message(result->error_message,
                      "Could not allocate memory for key context: ");
    goto create_key_end;
  }

  if (EVP_PKEY_fromdata_init(key_context) != SUCCESS) {
    set_error_message(result->error_message,
                      "Could not initializes a context for key import: ");
    goto create_key_end;
  }

  if (EVP_PKEY_fromdata(key_context, key, EVP_PKEY_KEYPAIR, params) !=
      SUCCESS) {
    set_error_message(result->error_message,
                      "Could not create structure to store public key: ");
    goto create_key_end;
  }

  ret = SUCCESS;

create_key_end:
  EVP_PKEY_CTX_free(key_context);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(param_bld);

  return ret;
}

int create_signature_DER(unsigned char **signature_der, int *signature_der_len,
                         struct verify_result *result,
                         const char *signature_r_hex,
                         const char *signature_s_hex) {
  int ret = FAILURE;

  *signature_der = NULL;

  BIGNUM *signature_r = NULL;
  BIGNUM *signature_s = NULL;

  if (BN_hex2bn(&signature_r, signature_r_hex) == FAILURE) {
    set_error_message(result->error_message,
                      "Could not convert r of signature to BIGNUM: ");
    goto end_create_signature_DER;
  }

  if (BN_hex2bn(&signature_s, signature_s_hex) == FAILURE) {
    set_error_message(result->error_message,
                      "Could not convert s of signature to BIGNUM: ");
    goto end_create_signature_DER;
  }

  ECDSA_SIG *signature = NULL;
  if ((signature = ECDSA_SIG_new()) == NULL) {
    set_error_message(result->error_message,
                      "Could not allocate signature structure: ");
    goto end_create_signature_DER;
  }

  if (ECDSA_SIG_set0(signature, signature_r, signature_s) != SUCCESS) {
    set_error_message(result->error_message,
                      "Could not set r & s in signature struct: ");
    goto end_create_signature_DER;
  }

  if ((*signature_der_len = i2d_ECDSA_SIG(signature, signature_der)) < 0) {
    set_error_message(result->error_message,
                      "Could not encode signature to DER format: ");
    goto end_create_signature_DER;
  }

  ret = SUCCESS;

end_create_signature_DER:
  ECDSA_SIG_free(signature);

  return ret;
}

void set_error_message(char *buffer, const char *message_prefix) {
  const char *file = NULL, *func = NULL, *data = NULL;
  int line = 0, flags = 0;

  ERR_get_error_all(&file, &line, &func, &data, &flags);

  snprintf(buffer, 256, "%s: file: %s:%d: function: %s, data: %s, flags: %d\n",
           message_prefix, file, line, func, data, flags);
}