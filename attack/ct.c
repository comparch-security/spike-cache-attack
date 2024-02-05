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

#define DPRINT

////////////////////////////////////////////////////////////////////////////////
// Function declarations

int ct(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, uint64_t drain, int* evset_len);

////////////////////////////////////////////////////////////////////////////////

void attacker(){
  uint64_t *evict_mem;
  uint64_t *drain_mem;
  mem_map_shared(&evict_mem, EVICT_LLC_SIZE, usehugepage);
  mem_map_shared(&drain_mem, EVICT_LLC_SIZE, usehugepage);

  uint64_t succ = 0 ;
  uint64_t target_index, target_addr;
  uint64_t evset[32];
  int evset_len;
  for (uint64_t t=0; t<TEST_LEN; t++) {
    target_index = ((rand() % SHARED_MEM_SIZE) >> 3) & (~0x7ull);
    target_addr = (uint64_t)(shared_mem + target_index);
    evset_len = 0;

    if(ct(evset, 32, target_addr, LLC_WAYS, (uint64_t)evict_mem, (uint64_t)drain_mem, &evset_len)) {
      succ++;
      char disp = 0;
      if(succ == 1) disp = 1;
      else if(1       <= succ && succ <      10) { if(succ % 1     == 0) disp = 1; }
      else if(10      <= succ && succ <     100) { if(succ % 10    == 0) disp = 1; }
      else if(100     <= succ && succ <    1000) { if(succ % 100   == 0) disp = 1; }
      else if(1000    <= succ && succ <   10000) { if(succ % 1000  == 0) disp = 1; }
      else if(10000   <= succ                  ) { if(succ % 10000 == 0) disp = 1; }

      if(disp)
        printf("Success. traget 0x%lx succ-rate %ld/%ld=%3.2f%%\n", target_addr, succ, t+1, (float)(100*succ)/(t+1));
    }
  }
  printf(" finish succ-rate %ld/%ld=%f%%\n", succ, (uint64_t)TEST_LEN, (float)(100*succ)/TEST_LEN);

  KILL_HELPER();
  mem_unmap(evict_mem,  EVICT_LLC_SIZE);
  mem_unmap(drain_mem,  EVICT_LLC_SIZE);
}

int ct(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, uint64_t drain, int* evset_len){

  printf("enter ct test.\n");

  static uint64_t prime_index  = 0;
  *evset_len = 0;
#ifdef DPRINT
  int prime_len = 0;
#endif

  do {
    if(prime_index >= MAX_POOL_SIZE) prime_index = 0;

    HELPER_READ_ACCESS(victim);
    printf("helper read %lx.\n", victim);

    while(1) {
      uint64_t addr = CAL_SATRT_ADDR(page, victim, prime_index);
      prime_index++;
#ifdef DPRINT
      prime_len++;
      printf(".");
#endif

      // preload TLB
      uint64_t addr_preload = addr ^ 0x800ull;
      READ_ACCESS(addr_preload);
      fence();
      if(!HELPER_CHECK(victim)) continue;

      // test
      READ_ACCESS(addr);
      fence();
      if(!HELPER_CHECK(victim)) {
        evset[*evset_len] = addr;
        *evset_len += 1;
#ifdef DPRINT
        printf("find %d evset element by prime %d address.\n", *evset_len, prime_len);
#endif
        break;
      }
    }
  } while(*evset_len < nway);

  // check evset
  int coloc_count = 0;
  HELPER_SET_COLOC(victim);
  for(int i=0; i<*evset_len; i++)
    if(CHECK_COLOC(evset[i])) coloc_count++;

#ifdef DPRINT
  printf("evset contains %d coloc addresses.\n", coloc_count);
#endif
  if(coloc_count >= nway) return 1;

  return 0;
}
