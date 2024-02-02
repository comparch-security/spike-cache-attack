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

////////////////////////////////////////////////////////////////////////////////
// Function declarations

int ctpp(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, uint64_t drain, int* evset_len);
void test_ctpp();

////////////////////////////////////////////////////////////////////////////////

void attacker() {
  test_ctpp();
}

void test_ctpp(){
  uint64_t *evict_mem;
  uint64_t *drain_mem;
  mem_map_shared(&evict_mem, EVICT_LLC_SIZE, usehugepage);
  mem_map_shared(&drain_mem, EVICT_LLC_SIZE, usehugepage);

  printf("both evict and drain are mapped.\n");

  // premap
  /*
  for (int i=0; i<EVICT_LLC_SIZE/8; i+=128)
    evict_mem[i] = 0x1;
  for (int i=0; i<EVICT_LLC_SIZE/8; i+=128)
    evict_mem[i] = 0x0;
  */

  uint64_t succ = 0 ;
  for (uint64_t t=0; t<TEST_LEN; t++) {
    uint64_t target_index = (random_fast() % SHARED_MEM_SIZE) & (~0x7ull);
    uint64_t target_addr = (uint64_t)(shared_mem + target_index);
    uint64_t evset[32];
    int evset_len = 0;

    if(ctpp(evset, 32, target_addr, LLC_WAYS, (uint64_t)evict_mem, (uint64_t)drain_mem, &evset_len)) {
      succ++;
      char disp = 0;
      if(succ == 1) disp = 1;
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
  mem_unmap(evict_mem,  EVICT_LLC_SIZE);
}

int ctpp(uint64_t *evset, int evset_max, uint64_t victim, int nway, uint64_t page, uint64_t drain, int* evset_len){

  static uint64_t prime_index  = 0;
  static uint64_t drain_index  = 0;

  if(prime_index + prime_pool_len >= MAX_POOL_SIZE) prime_index = 0;
  if(drain_index + drain_pool_len >= MAX_POOL_SIZE) drain_index = 0;

  //CTPP STEP 0: drain out (and force LRU?)
  SEQ_ACCESS(drain, victim, drain_index, drain_pool_len);
  drain_index += drain_pool_len;

  printf("cache drained.\n");

  HELPER_READ_ACCESS(victim);

  printf("victim accessed.\n");

  KILL_HELPER();
  exit(0);

  // CTPP STEP 1: prime until evict the victim
  int prime_index_start = prime_index, prime_len = 0, failed = 0;
  while(1) {
    const int step_size = 20;
    SEQ_ACCESS(page, victim, prime_index, step_size);
    prime_index += step_size;
    prime_len   += step_size;

    fence();
    if(!HELPER_CHECK(victim)) break;
    if(prime_len > prime_pool_len - step_size + 1) { failed = 1; break; }
  }

  if(failed) return 0;

  int pp_round = 0;
  uint64_t *evset_mask = NULL;
  do {
    // CTPP STEP2: remove hit
    if(evset_mask) free(evset_mask);
    evset_mask  = (uint64_t*)calloc(prime_pool_len/64, sizeof(uint64_t));

    uint64_t probe = CAL_SATRT_ADDR(page, victim, prime_index_start);
    for(int i=0; i<prime_len; i++, probe+=SEQ_OFFSET) {
      if(!CHECK_ACCESS(probe))
        evset_mask[i>>6] |= (1ull << (i&0x3f));
    }

    // CTPP STEP3: remove miss
    probe = CAL_SATRT_ADDR(page, victim, prime_index_start);
    *evset_len = 0;
    for(int i=0; i<prime_len; i++, probe+=SEQ_OFFSET) {
      if(evset_mask[i>>6] & (1ull << (i&0x3f))) {
        if(!CHECK_ACCESS(probe))
          evset_mask[i>>6] &= ~(1ull << (i&0x3f));
        else
          *evset_len += 1;
      }
    }
  } while(++pp_round < 2 && *evset_len > evset_max);


  if(*evset_len > evset_max) return 0;

  // collect evset
  uint64_t ev_elem = CAL_SATRT_ADDR(page, victim, prime_index_start);
  for(int i=0, ei=0; i<prime_len; i++, ev_elem+=SEQ_OFFSET) {
    if(evset_mask[i>>6] & (1ull << (i&0x3f)))
      evset[ei++] = ev_elem;
  }

  // check evset
  int coloc_count = 0;
  SET_COLOC(victim);
  for(int i=0; i<*evset_len; i++)
    if(CHECK_COLOC(evset[i])) coloc_count++;
    
  if(coloc_count >= nway) return 1;

  return 0;
}
