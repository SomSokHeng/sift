CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -lm

SRC = src/main.c src/magic.c src/entropy.c src/scan.c src/classify.c src/report.c src/sha.c
OBJ = $(SRC:.c=.o)
BIN = sift

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c src/sift.h src/sha.h
	$(CC) $(CFLAGS) -c -o $@ $<

check: $(BIN)
	./$(BIN) --version
	./$(BIN) --help

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all check clean
