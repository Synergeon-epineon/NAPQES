# Makefile for the C port of napqes.
# Targets: napqes_demo (default), clean.

CC      ?= cc
# -ffp-contract=off: the legacy v7 noise schedule still derives its threshold
# in IEEE-754 double. Contracting `0.75 + t * (0.99 - 0.75)` into an FMA drops
# a rounding step, which changes the threshold by 1 ULP on FMA-capable targets
# and desynchronises this port from the Python and Rust ones. The v8 schedule
# is integer-only and unaffected.
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -ffp-contract=off
LDFLAGS ?=
LDLIBS  ?=

ifeq ($(OS),Windows_NT)
    LDLIBS += -lbcrypt
    EXE := .exe
else
    EXE :=
endif

SRC := sha256.c base64.c napqes.c main.c
OBJ := $(SRC:.c=.o)

napqes_demo$(EXE): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) napqes_demo napqes_demo.exe test_kats test_kats.exe test_kats.o napqes_test.o kat-test kat-test.exe

# napqes_test.o is a separate compilation of napqes.c with
# NAPQES_ENABLE_TEST_NONCE_API defined, exposing napqes_encrypt_bytes_with_nonce
# (deterministic-nonce encrypt) for the KAT harness only. The default
# napqes.o (used by napqes_demo) does NOT define this macro, so that
# symbol is absent from the production build/library — see docs/CAVEATS.md
# (CVF3): an explicit, caller-chosen nonce is a key-recovery hazard for
# NAPQES and must not be reachable outside testing.
napqes_test.o: napqes.c napqes.h
	$(CC) $(CFLAGS) -DNAPQES_ENABLE_TEST_NONCE_API -c -o napqes_test.o napqes.c

kat-test$(EXE): test_kats.c sha256.o base64.o napqes_test.o
	$(CC) $(CFLAGS) $(LDFLAGS) -DNAPQES_ENABLE_TEST_NONCE_API -o kat-test$(EXE) test_kats.c sha256.o base64.o napqes_test.o $(LDLIBS)

.PHONY: clean kat-test
