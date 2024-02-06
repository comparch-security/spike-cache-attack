#pragma once

#include <stdint.h>

#define read_csr(reg) ({ uint64_t tmp; asm volatile ("csrr %0, " #reg : "=r"(tmp)); tmp; })
#define write_csr(reg, val) ({ asm volatile ("csrw " #reg ", %0" :: "r"(val)); })

#define READ_ACCESS(p) ({ asm volatile ("ld t0, (%0);" : : "r" (p) : "t0"); })
#define WRITE_ACCESS(p)  ({ fence(); asm volatile ("li t0, 10; sd t0, (%0);" : : "r"(v) : "t0"); fence(); })
#define mread(p)   ({ int rv = 0; asm volatile("lw %0, (%1);": "+r" (rv): "r" (v):); rv; })

#include "flexicas/flexicas-pfc.h"
#define MAKE_CMD(p, cmd) (((uint64_t)(p) & FLEXICAS_PFC_ADDR)|cmd)
#define READ_PFC() read_csr(0x8F0)
#define WRITE_PFC(cmd) ({ uint64_t __cmd = cmd; write_csr(0x8F0, __cmd); })

#define fence() WRITE_PFC(FLEXICAS_PFC_FENCE)
#define flush_nofence(p) WRITE_PFC(MAKE_CMD(p, FLEXICAS_PFC_FLUSH))
#define FLUSH(p) { fence(); WRITE_PFC(MAKE_CMD(p, FLEXICAS_PFC_FLUSH)); fence(); }


#define llc_hit(p) ({ WRITE_PFC(MAKE_CMD(p, FLEXICAS_PFC_QUERY)); READ_PFC(); })
#define CHECK_ACCESS(p) ({ WRITE_PFC(MAKE_CMD(p, FLEXICAS_PFC_QUERY)); READ_ACCESS(p); READ_PFC(); })
#define SET_COLOC(p) ({ WRITE_PFC(MAKE_CMD(p, FLEXICAS_PFC_CONGRU_TARGET)); })
#define CHECK_COLOC(p) ({ WRITE_PFC(MAKE_CMD(p, FLEXICAS_PFC_CONGRU_QUERY)); READ_PFC(); })
