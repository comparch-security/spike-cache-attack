#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "misc_utils.h"

// Pin thread to specific core
void set_core(int core, char *print_info) {

  // Define your cpu_set bit mask
  cpu_set_t my_set;

  // Initialize it all to 0, i.e. no CPUs selected
  CPU_ZERO(&my_set);

  // Set the bit that represents core
  CPU_SET(core, &my_set);

  // Set affinity of this process to the defined mask
  sched_setaffinity(0, sizeof(cpu_set_t), &my_set);

  // Print this thread's CPU
  printf("Core %2d for %s\n", sched_getcpu(), print_info);
}
