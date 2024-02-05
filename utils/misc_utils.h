#pragma once

#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <time.h>

void set_core(int core, char *print_info);
