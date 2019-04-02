SRC=$(wildcard *.c)
OBJ=$(patsubst %.c, %.o, $(SRC))

CFLAGS_COMMON=-pedantic -w -Wextra -Wno-long-long -march=native

CFLAGS=$(CFLAGS_COMMON) -O3 -fomit-frame-pointer


bench:		$(SRC)
			$(CC) $(CFLAGS) $^ -o bench -lcrypto
			./bench

clean:
			rm -f bench *.dSYM *.o

.PHONY: clean format analyze cloc bench

