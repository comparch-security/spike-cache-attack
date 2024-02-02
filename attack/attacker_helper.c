#include <stdio.h>
#include <stdlib.h>
#include <sched.h>

#include "attack.h"

void attacker_helper() {

  while(1) {
    while(ht_params->fun == HPT_FUN_IDLE) sched_yield();

    uint64_t fun         = ht_params->fun;
    uint64_t page        = ht_params->page;
    uint64_t addr        = ht_params->addr;
    uint64_t idx         = ht_params->idx;
    uint64_t len         = ht_params->len;

    //acc_syn
    if(fun == HPT_FUN_ACC_SYN) {
      READ_ACCESS(addr);
      ht_params->rv = 1;
    }

    //acc_asyn
    if(fun == HPT_FUN_ACC_SEQ) {
      SEQ_ACCESS(page, addr, idx, len);
      ht_params->rv = 1;
    }

    //check
    if(fun == HPT_FUN_CHECK) {
      ht_params->rv = 1 + CHECK_ACCESS(addr);
    }

    if(fun == HPT_FUN_OCCUPY_WAY) {
      uint64_t evset = page;
      while(1) {
        for(int i = 0; i < len; i++)
          READ_ACCESS(evset + i*sizeof(uint64_t));
        if(ht_params->fun == HPT_FUN_ABORT) break;
      }
      ht_params->rv = 1;
    }

    if(fun == HPT_FUN_SCH_YIELD) {
      ht_params->rv = 1;
      sched_yield();
    }

    if(fun == HPT_FUN_EXIT){
      printf("attacker_helper() exit\n");
      break;
    }

    ht_params->fun = HPT_FUN_IDLE;
  }

  ht_params->rv  = 1;
  exit(EXIT_SUCCESS);
}
