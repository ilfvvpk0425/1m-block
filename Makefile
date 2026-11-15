CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion
SAN     := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all

CORE    := src/domainset.c src/sniff.c
HDRS    := src/domainset.h src/sniff.h

all: 1m-block

1m-block: src/main.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) -o $@ src/main.c $(CORE) -lnetfilter_queue -lnfnetlink

test: tests/test.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) $(SAN) -o build-test tests/test.c $(CORE)
	./build-test

bench: bench/bench.c $(CORE) $(HDRS)
	$(CC) $(CFLAGS) -O3 -march=native -o build-bench bench/bench.c $(CORE)

clean:
	rm -f 1m-block build-test build-bench test_list.tmp

.PHONY: all test bench clean
