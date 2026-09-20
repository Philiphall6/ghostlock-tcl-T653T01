#ifndef TCL_V643_MCAST_CARRIER_H
#define TCL_V643_MCAST_CARRIER_H

#include <stdint.h>
#include <string.h>

#include "mcast_geometry.h"
#include "stack_geometry.h"

/* Byte-exact user buffer copied by compat ip_setsockopt.  Kernel pointers
 * remain uint64_t even though the producer must be an AArch32 process. */
struct tcl_v643_mcast_carrier {
  uint8_t bytes[TCL_V643_MCAST_COMPAT_COPY_SIZE];
};

static inline void tcl_v643_build_mcast_carrier(
    struct tcl_v643_mcast_carrier *carrier, uint64_t fake_task,
    uint64_t fake_lock, uint32_t wake_state, int32_t prio) {
  uint64_t wake_prio = (uint64_t)wake_state | ((uint64_t)(uint32_t)prio << 32);
  const unsigned base = TCL_V643_MCAST_COMPAT_WAITER_OFF;

  memset(carrier, 0, sizeof(*carrier));
  memcpy(carrier->bytes + base + TCL_V643_WAITER_TASK,
         &fake_task, sizeof(fake_task));
  memcpy(carrier->bytes + base + TCL_V643_WAITER_LOCK,
         &fake_lock, sizeof(fake_lock));
  memcpy(carrier->bytes + base + TCL_V643_WAITER_WAKE_STATE,
         &wake_prio, sizeof(wake_prio));
}

#endif
