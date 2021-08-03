PATHU = unity/src/
PATHS = src/
PATHT = test/
PATHB = build/
PATHO = build/objs/
PATHR = build/results/
PATHL = build/libs/
PATHRE = release/
PATHRO = build/release/objs/
PATH_OPENSSL = openssl/
PATH_OPENSSL_INCLUDE = openssl/include/

ifeq ($(OS),Windows_NT)
  ifeq ($(shell uname -s),) # not in a bash-like shell
	CLEANUP = del /F /Q
	MKDIR = mkdir
	COPY = copy
  else # in a bash-like shell, like msys
	CLEANUP = rm -f
	MKDIR = mkdir -p
  endif
	TEST_EXTENSION=exe
	LIBRARY_EXTENSION=dll
else
	CLEANUP = rm -f
	MKDIR = mkdir -p
	COPY = cp
	TEST_EXTENSION=out
	ifeq ($(shell uname -s),Darwin) # on MacOS
		LIBRARY_EXTENSION=dylib
		OPENSSL_LIB_CRYPTO=$(PATH_OPENSSL)libcrypto.3.$(LIBRARY_EXTENSION)
	else # on Linux
		LIBRARY_EXTENSION=so
		OPENSSL_LIB_CRYPTO=$(PATH_OPENSSL)libcrypto.$(LIBRARY_EXTENSION).3
	endif
endif

.PHONY: clean
.PHONY: test

CRYPTO_LIB=besu_native_ec_crypto
CRYPTO_LIB_PATH=$(PATHL)lib$(CRYPTO_LIB).$(LIBRARY_EXTENSION)

BUILD_PATHS = $(PATHB) $(PATHO) $(PATHR) ${PATHL}

SRCT = $(wildcard $(PATHT)*.c)

COMPILE=gcc -c -Wall -Werror -std=c11 -O3 -fPIC
LINK=gcc -L$(PATHL) -Wl,-rpath $(PATHL)
COMPILE_FLAGS=-I. -I$(PATHU) -I$(PATHS) -I$(PATH_OPENSSL_INCLUDE) -DTEST

RESULTS = $(patsubst $(PATHT)test_%.c,$(PATHR)test_%.txt,$(SRCT) )

PASSED = `grep -s PASS $(PATHR)*.txt`
FAIL = `grep -s FAIL $(PATHR)*.txt`
IGNORE = `grep -s IGNORE $(PATHR)*.txt`

test: $(BUILD_PATHS) $(RESULTS) $(CRYPTO_LIB_PATH)
	@echo "-----------------------\nIGNORES:\n-----------------------"
	@echo "$(IGNORE)"
	@echo "-----------------------\nFAILURES:\n-----------------------"
	@echo "$(FAIL)"
	@echo "-----------------------\nPASSED:\n-----------------------"
	@echo "$(PASSED)"
	@echo "\nDONE"

	./check_failing_test.sh

$(PATHR)%.txt: $(PATHB)%.$(TEST_EXTENSION)
	-./$< > $@ 2>&1

$(PATHB)test_ec_sign.$(TEST_EXTENSION): $(CRYPTO_LIB_PATH) $(PATHO)test_ec_sign.o $(PATHO)ec_sign.o $(PATHO)ec_verify.o $(PATHO)ec_key_recovery.o $(PATHU)unity.o $(PATHO)constants.o $(PATHO)utils.o $(PATHO)ec_key.o
	$(LINK) -o $@ $^ -l$(CRYPTO_LIB) -lc
# ifeq must not be indented
ifeq ($(shell uname -s),Darwin)
	install_name_tool -change /usr/local/lib/libcrypto.3.dylib $(CRYPTO_LIB_PATH) $@
endif

$(PATHB)test_%.$(TEST_EXTENSION): $(CRYPTO_LIB_PATH) $(PATHO)test_%.o $(PATHO)%.o $(PATHU)unity.o $(PATHO)constants.o $(PATHO)utils.o $(PATHO)ec_key.o
	$(LINK) -o $@ $^ -l$(CRYPTO_LIB) -lc
# ifeq must not be indented
ifeq ($(shell uname -s),Darwin)
	install_name_tool -change /usr/local/lib/libcrypto.3.dylib $(CRYPTO_LIB_PATH) $@
endif

$(PATHO)%.o:: $(PATHT)%.c
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

$(PATHO)%.o:: $(PATHS)%.c
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

$(PATHO)%.o:: $(PATHU)%.c $(PATHU)%.h
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

$(PATHB):
	$(MKDIR) $(PATHB)

$(PATHO):
	$(MKDIR) $(PATHO)

$(PATHR):
	$(MKDIR) $(PATHR)

$(PATHRE):
	$(MKDIR) $(PATHRE)

$(PATHRO):
	$(MKDIR) $(PATHRO)

$(PATHL):
	$(MKDIR) $(PATHL)

$(CRYPTO_LIB_PATH): $(PATHL)
	$(COPY) $(OPENSSL_LIB_CRYPTO) $@
ifeq ($(shell uname -s),Linux)
	patchelf --set-soname lib$(CRYPTO_LIB).$(LIBRARY_EXTENSION) $@
endif

release_build: $(PATHRO)constants.o $(PATHRO)ec_key.o $(PATHRO)ec_key_recovery.o $(PATHRO)ec_sign.o $(PATHRO)ec_verify.o $(PATHRO)utils.o
	$(LINK) $^ -l$(CRYPTO_LIB) -fPIC -shared -o $(PATHRE)libbesu_native_ec.$(LIBRARY_EXTENSION)
	$(COPY) src/besu_native_ec.h $(PATHRE)
	$(COPY) $(CRYPTO_LIB_PATH) $(PATHRE)

$(PATHRO)%.o: $(PATHS)%.c $(PATHRO) $(PATHRE)
	$(COMPILE) $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

clean:
	$(CLEANUP) $(PATHO)*.o
	$(CLEANUP) $(PATHRO)*.o
	$(CLEANUP) $(PATHB)*.$(TEST_EXTENSION)
	$(CLEANUP) $(PATHR)*.txt
	$(CLEANUP) $(PATHRE)*.$(LIBRARY_EXTENSION) $(PATHRE)*.h
	$(CLEANUP) $(PATHL)*.*

.PRECIOUS: $(PATHB)test_%.$(TEST_EXTENSION)
.PRECIOUS: $(PATHO)%.o
.PRECIOUS: $(PATHR)%.txt
