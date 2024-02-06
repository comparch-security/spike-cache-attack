#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>

// Consider this file only if the target machine has inclusive caches
// according to configuration.h
#include "attack.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"

//#define DPRINT

////////////////////////////////////////////////////////////////////////////////
// Function declarations

int ppp(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, int* evset_len);

////////////////////////////////////////////////////////////////////////////////

void attacker(){
  uint64_t *evict_mem;
  mem_map_shared(&evict_mem, EVICT_LLC_SIZE, usehugepage);

  uint64_t succ = 0 ;
  uint64_t target_index, target_addr;
  uint64_t evset[32];
  int evset_len;

  for (uint64_t t=0; t<TEST_LEN; t++) {
    target_index = ((rand() % SHARED_MEM_SIZE) >> 3) & (~0x7ull);
    target_addr = (uint64_t)(shared_mem + target_index);
    evset_len = 0;

    if(ppp(evset, 32, target_addr, LLC_WAYS, (uint64_t)evict_mem, &evset_len)) {
      succ++;
      char disp = 0;
      if(succ == 1) disp = 1;
      else if(1       <= succ && succ <      10) { if(succ % 1     == 0) disp = 1; }
      else if(10      <= succ && succ <     100) { if(succ % 10    == 0) disp = 1; }
      else if(100     <= succ && succ <    1000) { if(succ % 100   == 0) disp = 1; }
      else if(1000    <= succ && succ <   10000) { if(succ % 1000  == 0) disp = 1; }
      else if(10000   <= succ                  ) { if(succ % 10000 == 0) disp = 1; }

      if(disp)
        printf("Success. traget 0x%lx evset len %d succ-rate %ld/%ld=%3.2f%%\n", target_addr, evset_len, succ, t+1, (float)(100*succ)/(t+1));
    }
  }
  printf(" finish succ-rate %ld/%ld=%f%%\n", succ, (uint64_t)TEST_LEN, (float)(100*succ)/TEST_LEN);

  KILL_HELPER();
  mem_unmap(evict_mem,  EVICT_LLC_SIZE);
}

int ppp(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, int* evset_len){

  static uint64_t prime_index  = 0;
  *evset_len = 0;

  do {
    do {
      if(prime_index + prime_pool_len >= MAX_POOL_SIZE) prime_index = 0;

#ifdef DPRINT
      HELPER_READ_ACCESS(victim); // otherwise set coloc may crash
#endif

      // preload TLB for prime pool
      SEQ_ACCESS(page, victim, prime_index, prime_pool_len);

      uint64_t *evset_mask = (uint64_t*)calloc(prime_pool_len/64, sizeof(uint64_t));
      uint64_t addr;
      int all_cached;
#ifdef DPRINT
      int addr_count = 0;
      int coloc_addr_count = 0;
#endif

      do {
        // PPP prime
        addr = CAL_SATRT_ADDR(page, victim, prime_index);
        for(int i=0; i<prime_pool_len; i++, addr += SEQ_OFFSET) {
          if(!(evset_mask[i>>6] & (1ull << (i&0x3f))))
            READ_ACCESS(addr);
        }

        // PPP prune
#ifdef DPRINT
        HELPER_SET_COLOC(victim);
        addr_count = 0;
        coloc_addr_count = 0;
#endif
        all_cached = 1;
        addr = CAL_SATRT_ADDR(page, victim, prime_index+prime_pool_len-1);
        for(int i=prime_pool_len-1; i>=0; i--, addr -= SEQ_OFFSET) {
          if(!(evset_mask[i>>6] & (1ull << (i&0x3f)))) {
#ifdef DPRINT
            addr_count++;
            if(CHECK_COLOC(addr)) coloc_addr_count++;
#endif
            if(!CHECK_ACCESS(addr)) {
              evset_mask[i>>6] |= (1ull << (i&0x3f));
              all_cached = 0;
            }
          }
        }
#ifdef DPRINT
        printf("[%d, %d]", addr_count, coloc_addr_count); fflush(stdout);
#endif
      } while(!all_cached);

      // enforce order again
      addr = CAL_SATRT_ADDR(page, victim, prime_index+prime_pool_len-1);
      for(int i=prime_pool_len-1; i>=0; i--, addr -= SEQ_OFFSET) {
        if(!(evset_mask[i>>6] & (1ull << (i&0x3f)))) READ_ACCESS(addr);
      }      

      // PPP probe
      HELPER_READ_ACCESS(victim);
      addr = CAL_SATRT_ADDR(page, victim, prime_index+prime_pool_len-1);
      for(int i=prime_pool_len-1; i>=0; i--, addr -= SEQ_OFFSET) {
        if(!(evset_mask[i>>6] & (1ull << (i&0x3f)))) {
          if(!CHECK_ACCESS(addr) && *evset_len < evset_max) {
            evset[*evset_len] = addr;
            *evset_len += 1;
          }
        }
      }

      prime_index += prime_pool_len;
#ifdef DPRINT
      printf("(%d)\n", *evset_len);
#endif
    } while(*evset_len < nway);

    // check evset
    int coloc_count = 0;
    HELPER_SET_COLOC(victim);
    for(int i=0; i<*evset_len; i++)
      if(CHECK_COLOC(evset[i])) coloc_count++;

#ifdef DPRINT
    printf("a %d elements evset contains %d coloc addresses.\n", *evset_len, coloc_count);
#endif
    if(coloc_count >= nway) return 1;
  } while (*evset_len < evset_max);

  return 0;
}
