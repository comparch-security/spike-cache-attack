#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <getopt.h>
#include <assert.h>
#define ASSERT(x) assert(x != -1)

#include "configuration.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"
#include "../list/list_struct.h"


int usehugepage;
int prime_pool_len;
int drain_pool_len;
int help;

////////////////////////////////////////////////////////////////////////////////
// Memory Allocations

uint64_t *shared_mem;
volatile uint64_t *synchronization;
volatile uint64_t *synchronization_params;

volatile helpThread_t *ht_params;

////////////////////////////////////////////////////////////////////////////////
// Function declarations

void attacker(int test_option);
void victim();

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{
  //////////////////////////////////////////////////////////////////////////////
  // Process command line arguments

  int option_index=0;
  usehugepage         = 0;
  prime_pool_len      = 8000;
  drain_pool_len      = 20000;
  help                = 0;

  while (1) {

    static struct option long_options[] = {
      {"usehugepage"         ,   no_argument,            0, 0  },
      {"prime_pool_len"      ,   required_argument,      0, 0  },
      {"drain_pool_len"      ,   required_argument,      0, 0  },
      {"help"                ,   no_argument,            0, 0  },
      {0                     ,   0          ,            0, 0  }};

    if (getopt_long(argc, argv, "", long_options, &option_index) == -1)
      break;

    if(option_index ==   5)   usehugepage                     = 1;
    if(option_index ==  10)   prime_pool_len                  = atoi(optarg);
    if(option_index ==  11)   drain_pool_len                  = atoi(optarg);
    if(option_index ==  13)   help                            = 1;
  }
  if(help) {
    printf("\texample:\n");
    printf("\txeon-4110:  ./app --llc_miss_thres=140 --prime_pool_len=7000 --drain_pool_len=10000\n");
    exit(0);
  }

  //////////////////////////////////////////////////////////////////////////////
  // Memory allocations

  // `shared_mem` is for addresses that the attacker and victim will share.
  // `synchronization*` are variables for communication between threads.

  ASSERT(mem_map_shared(&shared_mem, SHARED_MEM_SIZE, usehugepage));
  ASSERT(var_map_shared(&synchronization));
  
  ASSERT(var_map_shared_bacheblocks((volatile uint64_t **)(&ht_params), 4));
  printf("ht_params %p\n", ht_params);


  *shared_mem = 1;
  *synchronization = 0;

  attacker(option_index);


  //////////////////////////////////////////////////////////////////////////////
  // Memory de-allocations

  ASSERT(munmap(shared_mem, SHARED_MEM_SIZE));
  ASSERT(var_unmap(synchronization));
  ASSERT(var_unmap_shared_bacheblocks((volatile uint64_t *)(ht_params), 4));

  return 0;
}
