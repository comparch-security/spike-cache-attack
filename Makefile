
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

UTILS_HEADERS  = $(wildcard utils/*.h)
ATTACK_HEADERS = $(wildcard attack/*.h)

UTILS_OBJS     = utils/memory_utils.o utils/misc_utils.o
ATTACK_OBJS    = attack/attacker_helper.o attack/ctpp.o attack/ct.o 

all: ctpp-test ct-test

.PONY: all

$(UTILS_OBJS) : %o:%c $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(ATTACK_OBJS) : %o:%c $(ATTACK_HEADERS) $(UTILS_HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

ctpp-test: attack/main.c attack/attacker_helper.o attack/ctpp.o $(UTILS_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

ct-test: attack/main.c attack/attacker_helper.o attack/ct.o $(UTILS_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	-rm $(UTILS_OBJS) $(CACHE_OBJS)
	-rm ctpp-test ct-test

.PHONY: clean
