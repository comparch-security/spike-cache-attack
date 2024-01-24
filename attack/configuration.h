#pragma once

extern int usehugepage;
extern int ctppp;
extern int disableflushp2;
extern int onecore;
extern int ppp;
extern int prime_pool_len;
extern int drain_pool_len;
extern int llc_miss_thres;


////////////////////////////////////////////////////////////////////////////////
// Supported platforms for this PoC

#define YOUROWNPLATFORM 

#define LLC_INCLUSIVE 
#define LLC_WITH_16_WAY_4096_SET 

#include "cache_info.h"

////////////////////////////////////////////////////////////////////////////////
// Core allocation

/*
  As Prime+Scope is a cross-core channel, ensure that
  attacker and victim (and helper) reside on different physical cores.
  In case of a hyperthreaded machine, logical siblings can be learned, e.g.: 
  cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list 
*/
#define ATTACKER_CORE   1
#define HELPER_CORE     3
#define VICTIM_CORE     5
#define HELPER2_CORE    7
#define HELPER3_CORE    9
#define HELPER4_CORE    11

////////////////////////////////////////////////////////////////////////////////
// Application Specific Configuration

/* If huge pages are available, indicate it. */
#define HUGE_PAGES_AVAILABLE  1

#include "../utils/memory_sizes.h"    // For KB, MB, GB
#define EVICT_L1_SIZE         ( 8*MB)
#define EVICT_L2_SIZE         ( 8*MB)
/*#if LLC_SLICES > 8
  #define EVICT_LLC_SIZE      (1024*MB) // especially the 28-slice machines need larger pool
#else
  #define EVICT_LLC_SIZE      (1024*MB) // especially the 28-slice machines need larger pool
#endif*/
#define EVICT_LLC_SIZE        (1*GB) // especially the 28-slice machines need larger pool
#define SHARED_MEM_SIZE       (1*GB)
  // Pick memory sizes. EVICT_LLC_SIZE is important as it defines the size of
  // guess pool, which consists of addresses potentially congruent with the target
 
#define TEST_LEN  21000
#define MAX_EVSET_CONST_RETRY 25

// The parameters below are for tweaking the evset construction

#define RANDOMIZE_TARGET 1
  // Pick a random tests for every loop of the tests

#define RENEW_THRESHOLD 0
  // Recalculate the cache access threshold for every loop of the tests

#define PREMAP_PAGES 1
  // Ensure that all physical pages of the evset buffer (guess pool) are mapped (and not copy-on-write)
  // before the accessing them in the evset construction.
  // Important for small pages.

////////////////////////////////////////////////////////////////////////////////
// Eviction Set Construction (../evsets) Parameters

#define ENABLE_ALREADY_FOUND 1
  // Uses the premature list when finding a new congruent address.

#define ENABLE_EARLY_EVICTION_CHECK 1
  // Tests whether the premature list evicts the victim
  // before any guess is accessed.

#define ENABLE_EXTENSION 1
  // Tests whether the found list can evict the victim.
  // If this fails, extends the list until it evicts.

#define ENABLE_REDUCTION 1
  // Reduces the list length to LLC length
  // by removing the list elements if they don't help eviction
  // Should be used with ENABLE_EXTENSION.

#define RANDOMIZE_GUESS_POOL 1
  // The guess pool (addresses which might be congruent with the target) is
  // random. If disabled, an ordered list of addresses are used.

#define IGNORE_VERY_SLOW 1
  // If an access to the target is slow, the guess might have evicted it, hence
  // it should be congruent. However, if the acccess is too slow, then
  // something might have gone wrong.

/// Parameters

#define MAX_EXTENSION  32
#define MAX_ATTEMPT    20
//#define EARLY_TEST_LEN 10

// For access to the types and return values of evset
#include "../evsets/ps_evset.h"
