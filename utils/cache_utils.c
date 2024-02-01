/*
  These cache utils have been stitched together over time, including modifications.
  We try to attribute them to original sources where we can.
*/


#include <stdint.h>
#include "cache_utils.h"

#define read_csr(reg) ({ unsigned long __tmp; \
  asm volatile ("csrr %0, " #reg : "=r"(__tmp)); \
  __tmp; })

#define write_csr(reg, val) ({ \
  asm volatile ("csrw " #reg ", %0" :: "r"(val)); })

#include "flexicas/flexicas-pfc.h"

inline void fence() {
  write_csr(0x8F0, FLEXICAS_PFC_FENCE);
}

inline void clflush(void *p) {
  uint64_t cmd = ((uint64_t)(p) & FLEXICAS_PFC_ADDR)|FLEXICAS_PFC_FLUSH;
  write_csr(0x8F0, cmd);
}

inline void clflush_f(void *p) {
  uint64_t cmd = ((uint64_t)(p) & FLEXICAS_PFC_ADDR)|FLEXICAS_PFC_FLUSH;
  fence();
  write_csr(0x8F0, cmd);
  fence();
}

/*
inline
uint64_t
// https://github.com/cgvwzq/evsets/blob/master/micro.h
rdtsc()
{
	unsigned a, d;
	__asm__ volatile (
	"rdtsc\n"
	"mov %%edx, %0\n"
	"mov %%eax, %1\n"
	: "=r" (a), "=r" (d)
	:: "%rax", "%rbx", "%rcx", "%rdx");
	return ((uint64_t)a << 32) | d;
}

// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/
uint64_t rdtscp64() {
  uint32_t low, high;
  asm volatile ("rdtscp": "=a" (low), "=d" (high) :: "ecx");
  return (((uint64_t)high) << 32) | low;
}
*/

////////////////////////////////////////////////////////////////////////////////

inline
void
// Attribution: https://github.com/IAIK/flush_flush/blob/master/sc/cacheutils.h
maccess(void* p)
{
	__asm__ volatile ("ld t0, (%0);" : : "r" (p) : "t0");
}

inline 
void 
mwrite(void *v)
{
  fence();
  asm volatile ("li t0, 10; sd t0, (%0);" : : "r"(v) : "t0");
  fence();
}

inline 
int 
// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/
mread(void *v) 
{
  int rv = 0;
  asm volatile("lw %0, (%1);": "+r" (rv): "r" (v):);
  return rv;
}

inline
int 
// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/
time_mread(void *adrs) 
{
  fence();
  maccess(adrs);
  fence();
  return 0;
}

inline
int 
// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/ (modified)
time_mread_nofence(void *adrs) 
{
  maccess(adrs);
  return 0;
}

inline
int
// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/ (modified)
time_mread_nofence2(void *adrs0, void *adrs1)
{
  maccess(adrs0);
  maccess(adrs1);
  return 0;
}

inline
int
// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/ (modified)
time_mread_nofence3(void *adrs0, void *adrs1, void *adrs2)
{
  maccess(adrs0);
  maccess(adrs1);
  maccess(adrs2);
  return 0;
}

inline
int
time_flush(void *adrs)
{
  clflush(adrs);
  return 0;
}

inline
int
llc_hit(void *p)
{
  uint64_t cmd = ((uint64_t)(p) & FLEXICAS_PFC_ADDR)|FLEXICAS_PFC_QUERY;
  write_csr(0x8F0, cmd);
  return read_csr(0x8F0);
}

inline
int
check_mread(void *p)
{
  uint64_t cmd = ((uint64_t)(p) & FLEXICAS_PFC_ADDR)|FLEXICAS_PFC_QUERY;
  write_csr(0x8F0, cmd);
  maccess(p);
  return read_csr(0x8F0);
}

inline
void
set_coloc_target(void *p)
{
  uint64_t cmd = ((uint64_t)(p) & FLEXICAS_PFC_ADDR)|FLEXICAS_PFC_CONGRU_TARGET;
  write_csr(0x8F0, cmd);
}

inline
int
check_coloc(void *p)
{
  uint64_t cmd = ((uint64_t)(p) & FLEXICAS_PFC_ADDR)|FLEXICAS_PFC_CONGRU_QUERY;
  write_csr(0x8F0, cmd);
  return read_csr(0x8F0);
}
