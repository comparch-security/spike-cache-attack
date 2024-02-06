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

int ct_fast(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, int* evset_len);

////////////////////////////////////////////////////////////////////////////////

void attacker(){
  uint64_t *evict_mem;
  mem_map_shared(&evict_mem, EVICT_LLC_SIZE, usehugepage);

  uint64_t succ = 0 ;
  uint64_t target_index, target_addr;
  uint64_t evset[32];
  int evset_len;

  // preload TLB for the whole prime pool
  SEQ_ACCESS_W_OFF(evict_mem, 0, 0, MAX_POOL_SIZE, 4096);
  printf("TLB preloaded.\n");

  for (uint64_t t=0; t<TEST_LEN; t++) {
    target_index = ((rand() % SHARED_MEM_SIZE) >> 3) & (~0x7ull);
    target_addr = (uint64_t)(shared_mem + target_index);
    evset_len = 0;

    if(ct_fast(evset, 32, target_addr, LLC_WAYS, (uint64_t)evict_mem, &evset_len)) {
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

int ct_fast(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, int* evset_len){

  static uint64_t prime_index  = 0;
  *evset_len = 0;
#ifdef DPRINT
  int prime_len = 0;
#endif

  uint64_t addr_start = CAL_SATRT_ADDR(page, victim, 0);
  uint64_t addr = addr_start;

  do {
    do {
      HELPER_READ_ACCESS(victim);

      // cache back
      for(int i=0; i<*evset_len; i++)
        READ_ACCESS(evset[i]);

      while(1) {
        if(prime_index >= MAX_POOL_SIZE) prime_index = 0;
        else                             prime_index++;
#ifdef DPRINT
        prime_len++;
        if((prime_len % 1024) == 0) {
          printf(".");
          fflush(stdout);
        }
#endif

        // test
        READ_ACCESS(addr);
        fence();
        if(!HELPER_CHECK(victim)) {
          evset[*evset_len] = addr;
          *evset_len += 1;
#ifdef DPRINT
          printf("(%d)\n", prime_len);
#endif
          break;
        }

        // failed
        if(prime_index == 0) addr = addr_start;
        else                 addr += SEQ_OFFSET;
      }
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
