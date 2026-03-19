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

# OpenSSL is linked statically to avoid leaking symbols into the JVM process.
# See: https://github.com/hyperledger/besu-native/issues/XXX
OPENSSL_STATIC_LIB = $(PATH_OPENSSL)libcrypto.a

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
	else # on Linux
		LIBRARY_EXTENSION=so
	endif
endif

.PHONY: clean
.PHONY: test

BUILD_PATHS = $(PATHB) $(PATHO) $(PATHR) ${PATHL}

SRCT = $(wildcard $(PATHT)*.c)

COMPILE=gcc -c -Wall -Werror -std=c11 -O3 -fPIC
COMPILE_FLAGS=-I. -I$(PATHU) -I$(PATHS) -I$(PATH_OPENSSL_INCLUDE) -DTEST

# Link tests against the static OpenSSL library
LINK_TEST=gcc

# the following commands are used to create the console output of the tests
RESULTS = $(patsubst $(PATHT)test_%.c,$(PATHR)test_%.txt,$(SRCT) )

PASSED = `grep -s PASS $(PATHR)*.txt`
FAIL = `grep -s FAIL $(PATHR)*.txt`
IGNORE = `grep -s IGNORE $(PATHR)*.txt`

test: $(BUILD_PATHS) $(RESULTS)
	@echo "-----------------------\nIGNORES:\n-----------------------"
	@echo "$(IGNORE)"
	@echo "-----------------------\nFAILURES:\n-----------------------"
	@echo "$(FAIL)"
	@echo "-----------------------\nPASSED:\n-----------------------"
	@echo "$(PASSED)"
	@echo "\nDONE"

	./check_failing_test.sh

# the result files are created by executing the tests and writing all their output into it
$(PATHR)%.txt: $(PATHB)%.$(TEST_EXTENSION)
	-./$< > $@ 2>&1

# the sign test uses the verification and key recovery as well, therefore those are added to its dependencies
$(PATHB)test_ec_sign.$(TEST_EXTENSION): $(PATHO)test_ec_sign.o $(PATHO)ec_sign.o $(PATHO)ec_verify.o $(PATHO)ec_key_recovery.o $(PATHU)unity.o $(PATHO)constants.o $(PATHO)utils.o $(PATHO)ec_key.o
	$(LINK_TEST) $(CFLAGS) -o $@ $^ $(OPENSSL_STATIC_LIB) -lc

# the other test don't have other dependencies and are compiled on their own
$(PATHB)test_%.$(TEST_EXTENSION): $(PATHO)test_%.o $(PATHO)%.o $(PATHU)unity.o $(PATHO)constants.o $(PATHO)utils.o $(PATHO)ec_key.o
	$(LINK_TEST) $(CFLAGS) -o $@ $^ $(OPENSSL_STATIC_LIB) -lc

# creates the test object files from the test *.c files
$(PATHO)%.o:: $(PATHT)%.c
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

# creates the object file from the *.c files in src/
$(PATHO)%.o:: $(PATHS)%.c
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

# creates the object files from the unity (test framework) files
$(PATHO)%.o:: $(PATHU)%.c $(PATHU)%.h
	$(COMPILE) --debug $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

# the following commands create the directories of the build folder
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

# the release build links OpenSSL statically with all symbols hidden, exporting only p256_* functions.
# This prevents OpenSSL symbols from leaking into the JVM process and conflicting with other native
# libraries (e.g. SoftHSM2, cloud HSM PKCS#11 clients) that depend on system OpenSSL.
release_build: $(PATHRO)constants.o $(PATHRO)ec_key.o $(PATHRO)ec_key_recovery.o $(PATHRO)ec_sign.o $(PATHRO)ec_verify.o $(PATHRO)utils.o
	echo "{ global: p256_*; local: *; };" > $(PATHRE)version.script
	gcc -shared -fPIC \
		-Wl,-Bsymbolic \
		-Wl,--exclude-libs,ALL \
		-Wl,--version-script=$(PATHRE)version.script \
		$^ $(OPENSSL_STATIC_LIB) \
		-o $(PATHRE)libbesu_native_ec.$(LIBRARY_EXTENSION)
	$(COPY) src/besu_native_ec.h $(PATHRE)

$(PATHRO)%.o: $(PATHS)%.c $(PATHRO) $(PATHRE)
	$(COMPILE) $(CFLAGS) $(COMPILE_FLAGS) $< -o $@

clean:
	$(CLEANUP) $(PATHO)*.o
	$(CLEANUP) $(PATHRO)*.o
	$(CLEANUP) $(PATHB)*.$(TEST_EXTENSION)
	$(CLEANUP) $(PATHR)*.txt
	$(CLEANUP) $(PATHRE)*.$(LIBRARY_EXTENSION) $(PATHRE)*.h $(PATHRE)version.script
	$(CLEANUP) $(PATHL)*.*

.PRECIOUS: $(PATHB)test_%.$(TEST_EXTENSION)
.PRECIOUS: $(PATHO)%.o
.PRECIOUS: $(PATHR)%.txt
