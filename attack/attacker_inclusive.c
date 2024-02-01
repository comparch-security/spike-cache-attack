#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>
#define ASSERT(x) assert(x != -1)

// Consider this file only if the target machine has inclusive caches 
// according to configuration.h
#include "configuration.h"
#include "../utils/colors.h"
#include "../utils/cache_utils.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"

// Evset functions
#include "../evsets/list/list_traverse.h"
#include "../evsets/list/list_utils.h"

////////////////////////////////////////////////////////////////////////////////
// Memory Allocations
extern volatile uint64_t *shared_mem;
extern volatile uint64_t *synchronization;
extern volatile uint64_t *synchronization_params;

extern volatile helpThread_t* ht_params;

static uint64_t lsfr = 0x01203891;

void init_seed(uint64_t seed) {
  lsfr = seed;
}

uint64_t random_fast() {
  return lsfr++;
  uint64_t b63 = 0x1 & (lsfr >> 62);
  uint64_t b62 = 0x1 & (lsfr >> 61);
  lsfr = ((lsfr << 2) >> 1) | (b63 ^ b62);
  return lsfr;
}

////////////////////////////////////////////////////////////////////////////////
// Function declarations

int  ctpp_ps_evset  (uint64_t *evset, char *victim, int nway uint64_t* page, int is_huge, int* evset_len);
void test_ctpp();

////////////////////////////////////////////////////////////////////////////////

uint64_t *evict_mem;
uint64_t *drain_mem;
void new_attacker_helper();

void attacker(int test_option) {

  ASSERT(mem_map_shared(&evict_mem, (uint64_t)EVICT_LLC_SIZE, usehugepage));
  ASSERT(mem_map_shared(&drain_mem, (uint64_t)EVICT_LLC_SIZE, usehugepage));

  if (fork() == 0) {
    set_core(HELPER_CORE, "Attacker Helper");
    //new_attacker_helper(i);
    attacker_helper();
    return;
  }

  test_ctpp();
  ASSERT(munmap(evict_mem,  EVICT_LLC_SIZE));

  // Shut Down,Control the victim core
  *synchronization = -1;
  sleep(1);
}

void test_ctpp(){

  #include "macros.h"

  uint64_t succ = 0 ;

  #if PREMAP_PAGES == 1
    ps_evset_premap(evict_mem);
  #endif

  for (uint64_t t=0; t<TEST_LEN; t++) {

    uint64_t target_index = (random_fast()%100000)*8;
    uint64_t *target_addr = shared_mem + target_index;

    uint64_t  evsetArray[32];

    *evsetList_ptr = NULL;
    int evset_len = 0 ;
    int rv = ctpp_ps_evset(&evsetArray[0],
                          (char*)target_addr,
                          LLC_WAYS,
                          evict_mem,
                          0,
                          &evset_len);
    if (rv) {
      succ++;
      char disp = 0;
      if(succ == 1) disp = 1;
      else if(10      <= succ && succ <     100) { if(succ % 10    == 0) disp = 1; }
      else if(100     <= succ && succ <    1000) { if(succ % 100   == 0) disp = 1; }
      else if(1000    <= succ && succ <   10000) { if(succ % 1000  == 0) disp = 1; }
      else if(10000   <= succ                  ) { if(succ % 10000 == 0) disp = 1; }


      if(disp)
        printf(GREEN"\tSuccess. traget %p Constucted succrate %ld/%ld=%3.2f%%\n"NC,
               target_addr, succ, t+1, (float)(100*succ)/(t+1));
    }
  }
  printf("ctpp");
  printf(" finish succrate %ld/%ld=%f%%\n",
          succ, (uint64_t)TEST_LEN,  (float)(100*succ)/TEST_LEN);
  KILL_HELPER();
}

int ctpp_ps_evset  (uint64_t *evset, int evset_max, char *victim, int nway, uint64_t* page, int is_huge, int* evset_len){

  const int TRYMAX = 1;
  int try = 0;
  static uint64_t prime_index  = 0;
  static uint64_t drain_index  = 0;
  uint64_t max_pool_size = (is_huge) ? MAX_POOL_SIZE_HUGE : MAX_POOL_SIZE_SMALL;
  uint64_t offset = SMALLPAGE_PERIOD;

  do {
    if(prime_index + prime_pool_len >= max_pool_size) prime_index = 0;
    if(drain_index + drain_pool_len >= max_pool_size) drain_index = 0;

    //CTPP STEP 0: drain out (and force LRU?)
    uint64_t drain = (is_huge) ?
      ((uint64_t)drain_mem + ((uint64_t)victim & (LLC_PERIOD-1      )) + (drain_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
      ((uint64_t)drain_mem + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (drain_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    for(int i=0; i<drain_pool_len; i++, drain += offset)
      maccess((void*)drain);
    drain_index += drain_pool_len;

    HELPER_READ_ACCESS(victim);

    // CTPP STEP 1: prime until evict the victim
    int prime_index_start = prime_index, prime_len = 0;
    uint64_t prime = (is_huge) ?
      ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
      ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);

    int failed = 0;
    while(1) {
      const int step_size = 20;
      for(int i=0; i<20; i++, prime+=offset)
        maccess((void*)prime);
      prime_index += step_size;
      prime_len   += step_size;

      fence();
      if(!HELPER_CHECK(victim)) break;
      if(prime_len > prime_pool_len - step_size + 1) { failed = 1; break; }
    }

    if(failed) continue; // failed at CT step

    int pp_round = 0;
    do {
      // CTPP STEP2: remove hit
      if(evset_mask) free(evset_mask);
      evset_mask  = (uint64_t*)calloc(prime_pool_len/64, sizeof(uint64_t));
      uint64_t probe = (is_huge) ?
        ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
        ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);

      for(int i=0; i<prime_len; i++, probe+=offset) {
        if(!check_mread((uint8_t *)(probe)))
          evset_mask[i>>6] |= (1ull << (i&0x3f));
      }

      // CTPP STEP3: remove miss
      probe = (is_huge) ?
        ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
        ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);

      *evset_len = 0;
      for(int i=0; i<prime_len; i++, probe+=offset) {
        if(evset_mask[i>>6] & (1ull << (i&0x3f))) {
          if(!check_mread((uint8_t *)(probe)))
            evset_mask[i>>6] &= ~(1ull << (i&0x3f));
          else
            *evset_len += 1;
        }
      }
    } while(++pp_round < 2 && *evset_len > evset_max);


    if(*evset_len > evset_max) continue; // failed

    // collect evset
    probe = (is_huge) ?
      ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
      ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    for(int i=0, ei=0; i<prime_len; i++, probe+=offset) {
      if(evset_mask[i>>6] & (1ull << (i&0x3f)))
        evset[ei++] = probe;
    }

    // check evset
    int co_count = 0;
    set_congruent_target(victim);
    for(int i=0; i<*evset_len; i++)
      if(check_congrunet((uint8_t *)evset[i])) co_count++;
    
    if(co_count >= nway) return 1;
  } while(++try < TRYMAX);

  return 0;
}

