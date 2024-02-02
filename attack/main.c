#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <getopt.h>

#include "attack.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"


int usehugepage    = 0;
int prime_pool_len = 8000;
int drain_pool_len = 20000;

uint64_t *shared_mem;
helpThread_t *ht_params;

int main(int argc, char **argv)
{
  int option_index=0;
  int help=0;
  while (1) {
    static struct option long_options[] = {
      {"usehugepage"         ,   no_argument,            0, 0  },
      {"prime_pool_len"      ,   required_argument,      0, 0  },
      {"drain_pool_len"      ,   required_argument,      0, 0  },
      {"help"                ,   no_argument,            0, 0  },
      {0                     ,   0          ,            0, 0  }};

    if (getopt_long(argc, argv, "", long_options, &option_index) == -1)
      break;

    if(option_index ==   5)   usehugepage      = 1;
    if(option_index ==  10)   prime_pool_len   = atoi(optarg);
    if(option_index ==  11)   drain_pool_len   = atoi(optarg);
    if(option_index ==  13)   help             = 1;
  }
  if(help) {
    printf("example:\n");
    printf("  ./app --usehugepage --prime_pool_len=7000 --drain_pool_len=10000\n");
    exit(0);
  }

  //////////////////////////////////////////////////////////////////////////////
  // Memory allocations

  // `shared_mem` is for addresses that the attacker and victim will share.

  mem_map_shared(&shared_mem, SHARED_MEM_SIZE, usehugepage);
  mem_map_shared((uint64_t **)&ht_params, sizeof(helpThread_t), 0);
  ht_params->fun = HPT_FUN_IDLE;
  ht_params->rv = 0;

  *shared_mem = 1;

  if (fork() == 0) {
    set_core(1, "Attacker Helper");
    attacker_helper();
    return 0;
  }
  set_core(0, "Attacker"); 
  attacker(option_index);


  //////////////////////////////////////////////////////////////////////////////
  // Memory de-allocations

  mem_unmap(shared_mem, SHARED_MEM_SIZE);
  mem_unmap((uint64_t *)ht_params, sizeof(helpThread_t));

  return 0;
}
