
MODE ?=

MAKE = make
CC = riscv64-unknown-linux-gnu-gcc

CFLAGS_COMMON = -Wall -static -I. -I$(RISCV)/include -fPIC

ifeq ($(MODE), release)
    CFLAGS = $(CFLAGS_COMMON) -O2 -DNDEBUG
else ifeq ($(MODE), debug)
    CFLAGS = $(CFLAGS_COMMON) -O0 -g
else
    CFLAGS = $(CFLAGS_COMMON) -O2
endif

UTILS_HEADERS  = $(wildcard utils/*.hpp)
ATTACK_HEADERS = $(wildcard attack/*.hpp)

UTILS_OBJS     = utils/cache_utils.o utils/memory_utils.o utils/misc_utils.o
ATTACK_OBJS    = attack/attacker_helper.o attack/attacker_inclusive.o

all: ctpp-test

.PONY: all

$(UTILS_OBJS) : %o:%c $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(ATTACK_OBJS) : %o:%c $(ATTACK_HEADERS) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

ctpp_test: attack/main.c $(ATTACK_OBJS) $(UTILS_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm $(UTILS_OBJS) $(CACHE_OBJS)
	-rm ctpp-test

.PHONY: clean
