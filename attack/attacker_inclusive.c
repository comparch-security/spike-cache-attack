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

extern volatile helpThread_t* ht_params[HPTHREADS];

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

int  ctpp_ps_evset  (uint64_t *evset, char *victim, int len, uint64_t* page, int is_huge, int* evset_len);
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

////////////////////////////////////////////////////////////////////////////////

void test_ctpp(){

  //////////////////////////////////////////////////////////////////////////////
  // Include the function macros
  #include "macros.h"
  #define TIMERECORD 1000

  //////////////////////////////////////////////////////////////////////////////
  // Eviction Set Construction

  struct timespec tstart={0,0}, tend={0,0}; double timespan , timeall; timeall = 0;
  int seed = time(NULL); srand(seed);
  float timeLo = 0, timeMedi = 0, timeHi = 0, timerecord[TIMERECORD];
  uint64_t target_addr;
  uint64_t target_index = (random_fast()%1000)*8;
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  init_seed((uint64_t)tstart.tv_sec * 1000 + (uint64_t)tstart.tv_nsec);
  target_index    = (random_fast()%1000)*8;
  target_addr     = (uint64_t)&shared_mem[target_index];

  uint64_t succ = 0 ;

  // Only need helper for clean threshold calibration
  //KILL_HELPER(); 

  #if PREMAP_PAGES == 1
    ps_evset_premap(evict_mem);
  #endif

  for (uint64_t t=0; t<TEST_LEN; t++) {

    target_index    = (random_fast()%100000)*8;
    target_addr     = (uint64_t)&shared_mem[target_index];

    Elem  *evsetList;
    Elem **evsetList_ptr = &evsetList;
    uint64_t  evsetArray[32];
    for(uint8_t i = 0; i<32; i++) evsetArray[i] = 0;

    *evsetList_ptr = NULL;
    int evset_len = 0 ;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    int rv = ctpp_ps_evset(&evsetArray[0],
                          (char*)target_addr,
                          LLC_WAYS,
                          evict_mem,
                          0,
                          &evset_len);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    timespan = time_diff_ms(tstart, tend);
    timeall += timespan;
    timerecord[t%TIMERECORD] = timespan;
    if(t%TIMERECORD == TIMERECORD - 1) {
      qsort(timerecord, TIMERECORD, sizeof(float), comp);
      timeLo    = timerecord[0];
      timeMedi  = timerecord[TIMERECORD>>1];
      timeHi    = timerecord[TIMERECORD-1];
    }
    if (rv) {
      succ++;
      char disp = 0;
      if(succ == 1) disp = 1;
      else if(10      <= succ && succ <     100) { if(succ % 10    == 0) disp = 1; }
      else if(100     <= succ && succ <    1000) { if(succ % 100   == 0) disp = 1; }
      else if(1000    <= succ && succ <   10000) { if(succ % 1000  == 0) disp = 1; }
      else if(10000   <= succ                  ) { if(succ % 10000 == 0) disp = 1; }


      if(disp)
        printf(GREEN"\tSuccess. traget %p Constucted succrate %ld/%ld=%3.2f%%, %3.3f[%3.3f-%3.3f-%3.3f]ms\n"NC,
               (void*)target_addr, succ, t+1, (float)(100*succ)/(t+1), timeall/(t+1), timeLo, timeMedi, timeHi);
    }
    //else
      //printf(RED"\tFail. Could not construct  succrate %d/%d=%f \n"NC, succ, t+1,  (float)(succ)/(t+1));
  }
  printf("ctpp"); if(ctppp) printf("p" );
  printf(" finish succrate %ld/%ld=%f%% avertime= %f ms midtime= %f ms totaltime %f s\n",
          succ, (uint64_t)TEST_LEN,  (float)(100*succ)/TEST_LEN, timeall/TEST_LEN, timeMedi, (float)clock()/CLOCKS_PER_SEC);
  KILL_HELPER();
}

int ctpp_ps_evset  (uint64_t *evset, char *victim, int len, uint64_t* page, int is_huge, int* evset_len){

  const int CHECKS = 10;
  const int TRYMAX = 1;
  const int PAGAINS = 0;
  const int EVSET_LEN_MAX = 32;

  int i,j,k;
  int time;
  int try = 0;
  uint8_t pass[2];
  uint64_t mask;
  uint64_t offset;
  int timerecord[CHECKS];

  static uint64_t prime_index  = 0;
  static uint64_t drain_index  = 0;

  static uint32_t try_accumulated         = 0;
  static uint32_t succ_accumulated[2]     = {0, 0}; //dual core / single core

  static uint32_t prime_len_accumulated[2]   = {0, 0};
  static uint32_t p1_pool_len_accumulated[2] = {0, 0};
  static uint32_t p2_pool_len_accumulated[2] = {0, 0};
  static uint32_t p3_pool_len_accumulated[2] = {0, 0};
  static uint32_t p4_pool_len_accumulated[2] = {0, 0};

  uint64_t drain;
  uint64_t prime, prime_len;
  uint64_t probe;
  uint64_t *p1_mask=NULL, p1_pool_len=0;
  uint64_t *p2_pool=NULL, p2_pool_len=0;
  uint64_t *p3_pool=NULL, p3_pool_len=0;
  uint64_t *p4_pool=NULL, p4_pool_len=0;
  uint64_t evset_array[EVSET_LEN_MAX];
  uint64_t pagain;
  uint64_t max_pool_size = (is_huge) ? MAX_POOL_SIZE_HUGE : MAX_POOL_SIZE_SMALL;
  offset = (is_huge) ? LLC_PERIOD : SMALLPAGE_PERIOD;
  *evset_len = 0;

  do {
    try_accumulated ++;
    if(p1_mask != NULL) { free(p1_mask); p1_mask = NULL; }
    if(p2_pool != NULL) { free(p2_pool); p2_pool = NULL; }
    //if(p3_pool != NULL) { free(p3_pool); p3_pool = NULL; }
    //if(p4_pool != NULL) { free(p4_pool); p4_pool = NULL; }
    prime_len      = 0;
    p1_pool_len    = 0;
    p2_pool_len    = 0;
    p3_pool_len    = 0;
    p4_pool_len    = 0;
    if(prime_index + prime_pool_len > max_pool_size-10) prime_index = 0;
    if(drain_index + drain_pool_len > max_pool_size-10) drain_index = 0;
    for(i = 0; i<CHECKS; i++) timerecord[i] = 0;

    p1_mask  = (uint64_t*)malloc(sizeof(uint64_t)*(prime_pool_len/64+10));
    p2_pool  = (uint64_t*)malloc(sizeof(uint64_t)*(prime_pool_len+10));
    for(i = 0; i < prime_pool_len; i = i+8) {
      p1_mask[i/64] = 0;
      p2_pool[i]    = 0;
    }


    for(i=0; i<HPTHREADS && onecore == 0; i++) {
      while(ht_params[i]->rv == 0);
      ht_params[i]->is_huge      = is_huge;
      ht_params[i]->idx          = drain_index;
      ht_params[i]->reqlen       = drain_pool_len;
      ht_params[i]->victim       = (uint8_t*)victim;
      ht_params[i]->page         = (uint64_t)page;
      ht_params[i]->drain_mem    = (uint8_t*)drain_mem;
    }

    //CTPP STEP 0: drain out (and force LRU?)
    if(onecore == 0) {
      ht_params[0]->rv           = 0;
      ht_params[0]->fun          = HPT_FUN_DRAIN;
    }
    drain = (is_huge) ?
          ((uint64_t)drain_mem + ((uint64_t)victim & (LLC_PERIOD-1      )) + (drain_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
          ((uint64_t)drain_mem + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (drain_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    drain -= offset;
    for(i = 0; i < drain_pool_len; i++) {
      drain += offset;
      maccess((void*)drain);
    }
    drain_index += drain_pool_len;
    if((random_fast() & 0x07) == 0 && onecore == 0) {
      for(i=0; i<HPTHREADS; i++){
        while(ht_params[i]->rv == 0);
        ht_params[i]->rv  = 0;
        ht_params[i]->fun = HPT_FUN_SCH_YIELD;
      }
      sched_yield();
    }
    for(i=0; i<HPTHREADS; i++) {
      while(ht_params[i]->rv == 0);
    }

    if(onecore == 0) TOGHTER_READ_ACCESS((void*)victim);
    else             maccess((void*)victim);
    // CTPP STEP 1: prime until evict the victim
    i =0;j=1;
    int evicted = 0;
    int reqlen  = 20;
    int prime_index_start = prime_index;
    prime = (is_huge) ?
          ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
          ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    prime -= offset;
    while(1){
      prime += offset;
      maccess((void*)prime);
      if(onecore == 0) {
        if(is_huge) {
          HELPER_READ_ACCESS_NOBLK((void*)prime);
        } else {
          if(i % reqlen == 0 && is_huge == 0) {
            while(ht_params[0]->rv == 0);
            ht_params[0]->rv      = 0;
            ht_params[0]->reqlen  = reqlen;
            ht_params[0]->idx     = prime_index;
            ht_params[0]->fun     = HPT_FUN_ACC_ASYN;
          }
        }
      }
      i++; j++; prime_index++; prime_len++;
      time = time_mread_nofence((void*)victim);
      if(evicted == 1 && (j % reqlen == 0)) break;
      if(evicted == 0) {
        if (time > threshold) evicted = 1;
      }
      if(evicted && is_huge) break;
      if(prime_len > prime_pool_len) { prime_len = 0; break; }
    }
    if(onecore == 0) {
      while(ht_params[0]->rv == 0);
      HELPER_READ_ACCESS((void*)victim);
    }

    // CTPP STEP2: remove hit
    reqlen = 10;
    int ht_index  = prime_index_start;
    probe = (is_huge) ?
        ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
        ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    probe -= offset;
    for(i = 0, j = 1; i < prime_len; i++, j++) {
      probe += offset;
      time = time_mread_nofence((void*)probe);
      if(is_huge && onecore == 0) HELPER_READ_ACCESS_NOBLK((void*)probe);
      if((i & 0x3f) == 0) mask = 0;
      if (time>threshold) {
        p1_pool_len ++;
        mask |= ((uint64_t)1 << (i & 0x3f));
      }
      p1_mask[i>>6]  = mask;
      if(is_huge == 0 && onecore == 0) {
        if(j >= reqlen && (j % reqlen == 0 || j == prime_len)) {
          while(ht_params[0]->rv == 0);
          ht_params[0]->rv      = 0;
          ht_params[0]->reqlen  = reqlen;
          ht_params[0]->idx     = ht_index;
          ht_params[0]->fun     = HPT_FUN_ACC_ASYN;
          ht_index             += reqlen;
        }
      }
    }
    if(onecore == 0) while(ht_params[0]->rv == 0);

    // CTPP STEP3: remove miss
    probe = (is_huge) ?
          ((uint64_t)page + ((uint64_t)victim & (LLC_PERIOD-1      )) + (prime_index_start % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
          ((uint64_t)page + ((uint64_t)victim & (SMALLPAGE_PERIOD-1)) + (prime_index_start % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
    probe -= offset;
    for(i = 0, mask = 0; ; ) {
      do {
        mask = mask >> 1;
        if((i & 0x3f) == 0) mask = p1_mask[i>>6];
        probe += offset;
        i++;
      } while((mask & 0x01) == 0 && i < prime_len);
      if((mask & 0x01) == 0) break;
      time = time_mread_nofence((void*)probe);
      if(time<threshold) {
        p2_pool[p2_pool_len++] = probe;
      }
      if(onecore == 0) HELPER_READ_ACCESS_NOBLK(probe);
    }
    free(p1_mask); p1_mask = NULL;

    // CTPP STEP4: remove hit
    if(ctppp && disableflushp2 == 0) {
      FLUSH(victim);
      for(i = 0; i < p2_pool_len; i++){
        FLUSH(p2_pool[i]);
      }
      for(i = 0; i < p2_pool_len; i++){
        if(onecore == 0) TOGHTER_READ_ACCESS((void*)p2_pool[i]);
        else             maccess            ((void*)p2_pool[i]);
        asm volatile("lfence");
      }
    }
    if(onecore == 0) TOGHTER_READ_ACCESS((void*)victim);
    else             maccess            ((void*)victim);
    for(i = 0; i < p2_pool_len; i++){
      if(ctppp) {
        time = time_mread_nofence((void*)p2_pool[i]);
        if (time>threshold) {
          p2_pool[p3_pool_len++] = p2_pool[i];
        }
        if(onecore == 0) HELPER_READ_ACCESS((void*)p2_pool[i]);
        asm volatile("lfence");
      } else {
        p2_pool[p3_pool_len++] = p2_pool[i];
      }
    }

    p4_pool_len = p3_pool_len;
    // CTPP STEP5: remove miss
    /*for(i = 0; i < p3_pool_len ; i++) {
      p2_pool[p4_pool_len++] = p2_pool[i];
      if(ctppp) {
        time = time_mread_nofence((void*)p3_pool[i]);
        if(time<threshold) {
          p4_pool[p4_pool_len++] = p3_pool[i];
        }
        HELPER_READ_ACCESS((void*)p3_pool[i]);
      } else {
        p4_pool[p4_pool_len++] = p3_pool[i];
      }
    }*/

    // CTPP STEP5: loop
    /*for(i = 0; i < PAGAINS && p4_pool_len > len; i++) {
      uint64_t p4_pool_len_latch = p4_pool_len;
      p4_pool_len = 0;
      if(i % 2 == 0) {
        TOGHTER_READ_ACCESS((void*)victim);
        for(j = 0; j < p4_pool_len_latch ; j++) {
          time = time_mread_nofence((void*)p4_pool[j]);
          if(time>threshold) {
            p4_pool[p4_pool_len++] = p4_pool[j];
          }
        HELPER_READ_ACCESS((void*)p4_pool[j]);
        }
      } else {
        for(j = 0; j < p4_pool_len_latch ; j++) {
          time = time_mread_nofence((void*)p4_pool[j]);
          if(time<threshold) {
            p4_pool[p4_pool_len++] = p4_pool[j];
          }
        HELPER_READ_ACCESS((void*)p4_pool[j]);
        }
      }
    }*/

    //check
    pass[0] = 0;
    pass[1] = 0;
    if(1) {
      //dual_core_check
      for(i =0 ; i <1; i++) {
        TOGHTER_READ_ACCESS_NOBLK((void*)victim);
        for(j = 0; j<p4_pool_len; j++) {
          TOGHTER_READ_ACCESS_NOBLK((void*)p2_pool[j]);
        }
      }
      for(i =0 ; i <CHECKS; i++) {
        TOGHTER_READ_ACCESS_NOBLK((void*)victim);
        for(j=0; j<4; j++) {
          for(k = 0; k<p4_pool_len; k++) {
            TOGHTER_READ_ACCESS_NOBLK((void*)p2_pool[k]);
          }
        }
        //while(ht_params[0]->rv == 0);
        time = time_mread_nofence((void*)victim);
        if(time > threshold) pass[0]++;
        else break;
        //timerecord[i] = time;
      }
      if(pass[0] == CHECKS) {
        for(j = 0; j<p4_pool_len && *evset_len < EVSET_LEN_MAX; j++) {
          evset_array[*evset_len] = p2_pool[j];
          *evset_len = *evset_len + 1;
          if(*evset_len >= EVSET_LEN_MAX) break;
        }
        //single_core_check
        for(i =0 ; i <CHECKS; i++) {
          maccess((void*)victim);
          for(j=0; j<10; j++) {
            for(k = 0; k< *evset_len; k++) {
              maccess((void*)evset_array[k]);
            }
          }
          time = time_mread_nofence((void*)victim);
          if(time > threshold) pass[1]++;
          else break;
          //timerecord[i] = time;
        }
      }
      if(onecore == 1) {
        pass[1] = 0;
        for(i =0 ; i <CHECKS; i++) {
          maccess((void*)victim);
          for(j=0; j<10; j++) {
            for(k = 0; k< p4_pool_len; k++) {
              maccess((void*)p2_pool[k]);
            }
          }
          time = time_mread_nofence((void*)victim);
          if(time > threshold) pass[1]++;
          else break;
          //timerecord[i] = time;
        }
      }

      //minimize_evset
      /*if(pass == CHECKS) {
        for(uint8_t rmsel = 0; rmsel < *evset_len; ) {
          for(i = 0; i<CHECKS; i++) {
            for(j = 0; j<10; j++) {
              for(k = 0; k< *evset_len; k++) {
                if(k != rmsel) maccess((void*)evset_array[k]);
              }
            }
            time = time_mread_nofence((void*)victim);
            if(time < threshold) break;
          }
          if(i == CHECKS) {
            for(j = rmsel; j < *evset_len-1; j++) evset_array[j]=evset_array[j+1];
            *evset_len = *evset_len-1;
          } else {
            rmsel++;
          }
        }
      }*/


      free(p2_pool); p2_pool = NULL;
      //qsort(timerecord, CHECKS, sizeof(int), comp);
      prime_len_accumulated[0]   += prime_len;
      p1_pool_len_accumulated[0] += p1_pool_len;
      p2_pool_len_accumulated[0] += p2_pool_len;
      p3_pool_len_accumulated[0] += p3_pool_len;
      p4_pool_len_accumulated[0] += p4_pool_len;
      if((onecore == 0 && pass[0] == CHECKS) || (onecore !=0 && pass[1] == CHECKS)) {
        /*if(p4_pool_len == 0) {
          if(0) printf(CYAN"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        } else if(p4_pool_len < 16) {
          if(0) printf(BLUE"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        } else if(p4_pool_len > 20) {
          if(0) printf(YELLOW"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        } else {
          if(0) printf(WHITE"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        }*/
        if(0) printf(WHITE"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n"NC,
               (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
               (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
        // return evset
        for(i = 0; i < *evset_len; i++) {
          *(evset+i) = evset_array[i];
        }
        prime_len_accumulated[1]   += prime_len;
        p1_pool_len_accumulated[1] += p1_pool_len;
        p2_pool_len_accumulated[1] += p2_pool_len;
        p3_pool_len_accumulated[1] += p3_pool_len;
        p4_pool_len_accumulated[1] += p4_pool_len;

        if((succ_accumulated[0] != 0) && (succ_accumulated[0] % 1000 == 0)) {
          printf(RED"\tsucc_accumulated %d %d pool_size: [%d->%d->%d->%d->%d]\n"NC,
                 succ_accumulated[0], succ_accumulated[1],
                 prime_len_accumulated[1]   / succ_accumulated[0],
                 p1_pool_len_accumulated[1] / succ_accumulated[0],
                 p2_pool_len_accumulated[1] / succ_accumulated[0],
                 p3_pool_len_accumulated[1] / succ_accumulated[0],
                 p4_pool_len_accumulated[1] / succ_accumulated[0]);
            printf(RED"\ttry_accumulated %d pool_size: [%d->%d->%d->%d->%d]\n"NC,
                 try_accumulated,
                 prime_len_accumulated[0]   / try_accumulated,
                 p1_pool_len_accumulated[0] / try_accumulated,
                 p2_pool_len_accumulated[0] / try_accumulated,
                 p3_pool_len_accumulated[0] / try_accumulated,
                 p4_pool_len_accumulated[0] / try_accumulated);

        }

        succ_accumulated[0] ++;
        if((onecore == 0 && pass[0] == CHECKS) || (onecore !=0 && pass[1] == CHECKS)) succ_accumulated[1] ++;
        return 1;
      } else if(0) {
        printf("\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d] evsize %d\n",
                 (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
                 (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len, *evset_len);
      }
    }
  } while(++try < TRYMAX);
  if(p1_mask != NULL) { free(p1_mask); p1_mask = NULL; }
  if(p2_pool != NULL) { free(p2_pool); p2_pool = NULL; }
  if(p3_pool != NULL) { free(p3_pool); p3_pool = NULL; }
  if(p4_pool != NULL) { free(p4_pool); p4_pool = NULL; }
  if(0) printf(RED"\tvictim %p try:%d pagain:%d pass:%d time:[%d-%d-%d] pool_size: [%d->%d->%d->%d->%d]\n"NC,
        (void*)victim, (int)try, (int)pagain, pass[0], timerecord[0], timerecord[CHECKS>>1], timerecord[CHECKS-1],
        (int)prime_len, (int)p1_pool_len, (int)p2_pool_len, (int)p3_pool_len, (int)p4_pool_len);
  return 0;
}

