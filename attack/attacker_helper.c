#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "configuration.h"
#include "../utils/cache_utils.h"
#include "../utils/misc_utils.h"
#include "../list/list_struct.h"
#include "../evsets/ps_evset.h"

extern volatile uint64_t *shared_mem;
extern volatile uint64_t *synchronization;
extern volatile uint64_t *synchronization2;
extern volatile uint64_t *synchronization3;
extern volatile uint64_t *synchronization_params;

extern volatile helpThread_t* ht_params;

void attacker_helper() {

  //////////////////////////////////////////////////////////////////////////////
  // Prepare variables for test cache access times

  // Add a time limit to the helper process to prevent it from becoming a zombie process

  while(1) {  

    if (*synchronization == -1) {
      break;
    }
    if (*synchronization == 99) {
      // Implements the KILL_HELPER() macro
      *synchronization = 0;
      break;
    }
    if (*synchronization == 1) {
      /* Implements the HELPER_READ_ACCESS() macro */
      memread((void*)*synchronization_params); 
      fence();
      *synchronization = 0;
    }
  }
  *synchronization = 0;
  printf("attacker_helper exit\n");
  exit(EXIT_SUCCESS);

}

void new_attacker_helper() {

  //////////////////////////////////////////////////////////////////////////////
  // Prepare variables for test cache access times
  int i;

  volatile helpThread_t *myparams = ht_params;

  uint64_t drain, prime, time;

  // Add a time limit to the helper process to prevent it from becoming a zombie process
  while(true) {
    while(myparams->fun == HPT_FUN_IDLE) sched_yield();

    uint64_t fun         = myparams->fun;
    uint64_t victim      = (uint64_t)myparams->victim;
    uint64_t reqlen      = myparams->reqlen;
    uint64_t is_huge     = myparams->is_huge;
    uint64_t page        = myparams->page;
    uint64_t syn_addr    = (uint64_t)myparams->syn_addr;
    uint64_t offset      = (is_huge) ? LLC_PERIOD : SMALLPAGE_PERIOD;

    //drain
    if(fun == HPT_FUN_DRAIN) {
      uint64_t drain_mem   = (uint64_t)myparams->drain_mem;
      drain = is_huge ?
            (drain_mem + (victim & (LLC_PERIOD-1      )) + (myparams->idx % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
            (drain_mem + (victim & (SMALLPAGE_PERIOD-1)) + (myparams->idx % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
      drain -= offset;
      for(i=0; i<reqlen; i++) {
        drain += offset;
        maccess((void*)drain);
      }
      myparams->rv = 1;
    }

    //acc_syn
    if(fun == HPT_FUN_ACC_SYN) {
      memread((void*)syn_addr); 
      myparams->rv = 1;
    }

    //acc_asyn
    if(fun == HPT_FUN_ACC_ASYN) {
      prime = is_huge ?
            (page + (victim & (LLC_PERIOD-1      )) + (myparams->idx % MAX_POOL_SIZE_HUGE )*LLC_PERIOD      ):
            (page + (victim & (SMALLPAGE_PERIOD-1)) + (myparams->idx % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD);
      prime -= offset;
      for(i=0; i<reqlen; i++) {
        prime += offset;
        maccess((void*)prime);
      }
      myparams->rv = 1;
    }

    //check
    if(fun == HPT_FUN_CHECK) {
      myparams->rv = 1 + check_mread((void*)victim);
    }

    if(fun == HPT_FUN_OCCUPY_WAY) {
      uint8_t  i = 0;
      uint64_t evset[32];
      for(i = 0; i < 32; i++) {
        evset[i] = myparams->evset[i];
      }
      while(1) {
        //reqlen = myparams->reqlen;
        for(i = 0; i < myparams->reqlen; i++) {
          maccess((void*)evset[i]);
        }
        if(myparams->fun == HPT_FUN_ABORT) break;
      }
      myparams->rv = 1;
    }

    if(fun == HPT_FUN_SCH_YIELD) {
      myparams->rv = 1;
      sched_yield();
    }

    if(fun == HPT_FUN_EXIT){
      printf("new_attacker_helper%d exit\n", id);
      break;
    }

    myparams->fun = HPT_FUN_IDLE;
  }

  myparams->rv  = 1;
  exit(EXIT_SUCCESS);
}
