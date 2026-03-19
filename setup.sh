#!/bin/bash

if [[ "$OSTYPE" == "msys" ]]; then
	LIBRARY_EXTENSION=dll
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  LIBRARY_EXTENSION=so
elif [[ "$OSTYPE" == "darwin"* ]]; then
  LIBRARY_EXTENSION=dylib
fi

git submodule init
git submodule update

cd openssl

# Build OpenSSL as a static library with hidden visibility.
# This prevents OpenSSL symbols from leaking into the JVM process when
# libbesu_native_ec is loaded, which would otherwise conflict with other
# native libraries (e.g. PKCS#11 HSM providers) that depend on system OpenSSL.
./Configure no-shared -fPIC -fvisibility=hidden \
            enable-ec_nistp_64_gcc_128 no-stdio no-ocsp no-nextprotoneg no-module \
            no-legacy no-gost no-engine no-dynamic-engine no-deprecated no-comp \
            no-cmp no-capieng no-ui-console no-tls no-ssl no-dtls no-aria no-bf \
            no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa \
            no-ecdh no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 \
            no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool
make build_generated libcrypto.a

cd ../
