#pragma once

#include <stdint.h>
#include "../utils/cache_utils.h"

// glibale variables
extern int usehugepage;
extern int prime_pool_len;
extern int drain_pool_len;

// cache definitions
#define LLC_INCLUSIVE 
#define BLOCK_OFFSET      6
#define LLC_SLICES        1
#define LLC_WAYS          16
#define LLC_INDEX_BITS    (BLOCK_OFFSET + 12) // 4096 sets
#define LLC_PERIOD        (1 << LLC_INDEX_BITS)
#define LLC_SET_INDEX(x)  ({uint64_t index = ( x & ~((1 << BLOCK_OFFSET)-1)) & ((1 << LLC_INDEX_BITS)-1);index;})
#define SMALLPAGE_PERIOD    (1 << 12)

// attack definitions

#include "../utils/memory_sizes.h"    // For KB, MB, GB
#define EVICT_LLC_SIZE        (64*MB) // especially the 28-slice machines need larger pool
#define SHARED_MEM_SIZE       (8*MB)
#define MAX_POOL_SIZE_HUGE  (EVICT_LLC_SIZE/LLC_PERIOD)
#define MAX_POOL_SIZE_SMALL (EVICT_LLC_SIZE/SMALLPAGE_PERIOD)
#define MAX_POOL_SIZE       (usehugepage && MAX_POOL_SIZE_HUGE > MAX_POOL_SIZE_SMALL ? \
                             MAX_POOL_SIZE_HUGE : MAX_POOL_SIZE_SMALL)

#define TEST_LEN  1000

extern uint64_t *shared_mem;

// attack helper

#define FLUSH(x)         ({ flush((void*)x);       })
#define READ_ACCESS(x)   ({ maccess((void*)x);     })
#define WRITE_ACCESS(x)  ({ memwrite((void*)x);    })
#define CHECK_ACCESS(x)  ({ check_mread((void*)x); })
#define SET_COLOC(x)     ({ set_coloc_target((void*)x); })
#define CHECK_COLOC(x)   ({ check_coloc((void*)x); })

#define START_ADDR_HUGE(page, addr, idx)  \
  (page + (addr&(LLC_PERIOD-1)) + (idx % MAX_POOL_SIZE_HUGE)*LLC_PERIOD)

#define START_ADDR_SMALL(page, addr, idx)                               \
  (page + (addr&(SMALLPAGE_PERIOD-1)) + (idx % MAX_POOL_SIZE_SMALL)*SMALLPAGE_PERIOD)

#define CAL_SATRT_ADDR(page, addr, idx)                                 \
  (usehugepage ? START_ADDR_HUGE(page, addr, idx) : START_ADDR_SMALL(page, addr, idx))

#define SEQ_OFFSET                       \
  (usehugepage ? LLC_PERIOD : SMALLPAGE_PERIOD)

#define SEQ_ACCESS(page, addr, idx, len)           \
  uint64_t acc = CAL_SATRT_ADDR(page, addr, idx);  \
  for(int i=0; i<len; i++, acc+=SEQ_OFFSET)        \
    READ_ACCESS(acc)                               \

#define HPT_FUN_IDLE        0
#define HPT_FUN_ACC_SYN     1
#define HPT_FUN_ACC_SEQ     2
#define HPT_FUN_CHECK       3
#define HPT_FUN_SCH_YIELD   4
#define HPT_FUN_OCCUPY_WAY  5
#define HPT_FUN_ABORT       6
#define HPT_FUN_EXIT        7

typedef struct helpThread
{
  uint64_t     fun;
  uint64_t     page;
  uint64_t     addr;
  uint64_t     idx;
  uint64_t     len;
  uint64_t     rv;
} helpThread_t;

extern helpThread_t* ht_params;

void attacker_helper();
void attacker();

#define HELPER_READ_ACCESS(x)   ({               \
  while(ht_params->rv == 0) sched_yield();       \
  ht_params->rv           = 0;                   \
  ht_params->addr         = (uint64_t)(x);       \
  ht_params->fun          = HPT_FUN_ACC_SYN;     \
  while(ht_params->rv == 0) sched_yield();       })

#define HELPER_READ_ACCESS_NOBLK(x)   ({         \
  while(ht_params->rv == 0) sched_yield();       \
  ht_params->rv           = 0;                   \
  ht_params->addr         = (uint64_t)(x);       \
  ht_params->fun          = HPT_FUN_ACC_SYN;     })

#define HELPER_CHECK(x)   ({                     \
  while(ht_params->rv == 0) sched_yield();       \
  ht_params->rv           = 0;                   \
  ht_params->addr         = (uint64_t)(x);       \
  ht_params->fun          = HPT_FUN_CHECK;       \
  while(ht_params->rv == 0) sched_yield();       \
  ht_params->rv - 1;                             })

#define KILL_HELPER()   ({                       \
  ht_params->fun = HPT_FUN_EXIT;                 })

#define BUSY_WAIT() ({                           \
  for (i = 30000; i>0; i--)                      \
    sched_yield();                               })

