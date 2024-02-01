////////////////////////////////////////////////////////////////////////////////
// Basic Memory Operations

#define READ_ACCESS(x)  ({                                        \
  maccess((void*)x);                                              })

#define TIME_READ_ACCESS(x)  ({                                   \
  access_time = time_mread((void*)x);                             })

#define TIME_READ_ACCESS_NOFENCE(x)  ({                            \
  access_time = time_mread_nofence((void*)x);                     })

#define WRITE_ACCESS(x)  ({                                       \
  memwrite((void*)x);                                             })

#define FLUSH(x)  ({                                              \
  flush((void*)x);                                                })

#define TIME_FLUSH(x)  ({                                         \
  access_time = time_flush((void*)x);                             })
                                     

////////////////////////////////////////////////////////////////////////////////
// Memory Operations to be executed by the helper thread
/*
#define HELPER_READ_ACCESS(x)   ({                                \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization  = 1;                                           \
  while(*synchronization==1);                                      })
*/

#define HELPER_READ_ACCESS(x)   ({                             \
  while(ht_params->rv == 0) sched_yield();                     \
  ht_params->rv           = 0;                                 \
  ht_params->syn_addr     = (uint8_t*)(x);                     \
  ht_params->fun          = HPT_FUN_ACC_SYN;                   \
  while(ht_params->rv == 0) sched_yield();                     })

#define HELPER_CHECK(x)   ({                                   \
  while(ht_params->rv == 0) sched_yield();                     \
  ht_params->rv           = 0;                                 \
  ht_params->victim       = (uint8_t*)(x);                     \
  ht_params->fun          = HPT_FUN_CHECK;                     \
  while(ht_params->rv == 0) sched_yield();                     \
  ht_params->rv - 1;                                           })

#define HELPER_READ_ACCESS_NOBLK(x)   ({                       \
  while(ht_params->rv == 0) sched_yield();                     \
  ht_params->rv           = 0;                                 \
  ht_params->syn_addr     = (uint8_t*)(x);                     \
  ht_params->fun          = HPT_FUN_ACC_SYN;                  })

#define TOGHTER_READ_ACCESS(x)   ({                             \
  while(ht_params->rv == 0);                                    \
  ht_params->rv           = 0;                                  \
  ht_params->syn_addr     = (uint8_t*)(x);                      \
  ht_params->fun          = HPT_FUN_ACC_SYN;                    \
  maccess((void*)x);                                            \
  while(ht_params->rv == 0) sched_yield();                      })

#define TOGHTER_READ_ACCESS_NOBLK(x)   ({                       \
  while(ht_params->rv == 0) sched_yield();                      \
  ht_params->rv           = 0;                                  \
  ht_params->syn_addr     = (uint8_t*)(x);                      \
  ht_params->fun          = HPT_FUN_ACC_SYN;                    \
  maccess((void*)x);                                            })

#define KILL_HELPER()   ({                                          \
  ht_params->fun = HPT_FUN_EXIT;                                   })
  while(*synchronization==99);                                      })

#define HELPER_TIME_ACCESS(x)   ({                                 \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization = 3;                                            \
  while(*synchronization==3);                                      \
  access_time = *synchronization_params;                           })

////////////////////////////////////////////////////////////////////////////////
// Memory Operations to be executed by the victim thread

#define VICTIM_READ_ACCESS(x)   ({                                \
  *synchronization_params = (volatile uint64_t)x;                  \
  *synchronization = 11;                                           \
  while(*synchronization==11);                                     })

////////////////////////////////////////////////////////////////////////////////
// Extras

#define BUSY_WAIT() ({                                            \
  for (i = 30000; i>0; i--)                                       \
    asm volatile("nop;");                                         })
