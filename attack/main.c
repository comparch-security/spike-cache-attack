#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <getopt.h>

#include "attack.h"
#include "../utils/memory_utils.h"
#include "../utils/misc_utils.h"


int usehugepage    =    0;
int prime_pool_len = 1200;
int drain_pool_len =  800;

uint64_t *shared_mem;
helpThread_t *ht_params;

int main(int argc, char **argv)
{
  static struct option long_options[] = {
    {"huge"        , no_argument       , 0  , 'u' },
    {"prime-pool"  , required_argument , 0  , 'p' },
    {"drain-pool"  , required_argument , 0  , 'd' },
    {"help"        , no_argument       , 0  , 'h' },
    {0             , 0                 , 0  , 0   }};

  int c;
  while ((c = getopt_long(argc, argv, "up:d:h", long_options, NULL)) != -1) {
    switch(c) {
    case 'u': usehugepage = 1; break;
    case 'p': prime_pool_len = atoi(optarg); break;
    case 'd': drain_pool_len = atoi(optarg); break;
    case 'h':
      printf("example:\n");
      printf("  %s --huge --prime-pool 7000 --drain-pool 10000\n", argv[0]);
      exit(0);
    case ':':   /* missing option argument */
      printf("%s: option `-%c' requires an argument\n", argv[0], optopt);
      break;
    case '?':
    default:    /* invalid option */
      printf("%s: option `-%c' is invalid: ignored\n", argv[0], optopt);
    }
  }

  printf("running with option:");
  if(usehugepage) printf(" --huge");
  printf(" --prime-pool=%d --drain-pool=%d\n", prime_pool_len, drain_pool_len);
  printf("  MAX_POOL_SIZE=%d SEQ_OFFSET=%d\n", MAX_POOL_SIZE, SEQ_OFFSET);

  //////////////////////////////////////////////////////////////////////////////
  // Memory allocations

  // `shared_mem` is for addresses that the attacker and victim will share.

  mem_map_shared(&shared_mem, SHARED_MEM_SIZE, usehugepage);
  //printf("shared mem: %lx -- %lx size=%x\n", (uint64_t)(shared_mem), (uint64_t)(shared_mem)+SHARED_MEM_SIZE, SHARED_MEM_SIZE);
  *shared_mem = 1;

  mem_map_shared((uint64_t **)&ht_params, sizeof(helpThread_t), 0);
  ht_params->fun = HPT_FUN_IDLE;
  ht_params->rv = 1;

  if (fork() == 0) {
    set_core(1, "Attacker Helper");
    attacker_helper();
    return 0;
  }

  set_core(0, "Attacker"); 
  attacker();


  //////////////////////////////////////////////////////////////////////////////
  // Memory de-allocations

  mem_unmap(shared_mem, SHARED_MEM_SIZE);
  mem_unmap((uint64_t *)ht_params, sizeof(helpThread_t));

  return 0;
}
