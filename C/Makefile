# Makefile for the C port of napqes.
# Targets: napqes_demo (default), clean.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
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
	rm -f $(OBJ) napqes_demo napqes_demo.exe test_kats test_kats.exe test_kats.o

kat-test$(EXE): test_kats.c sha256.o base64.o napqes.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o kat-test$(EXE) test_kats.c sha256.o base64.o napqes.o $(LDLIBS)

.PHONY: clean kat-test
