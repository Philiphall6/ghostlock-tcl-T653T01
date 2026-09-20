#ifndef TCL_V643_MCAST_HELPER_PROTOCOL_H
#define TCL_V643_MCAST_HELPER_PROTOCOL_H

#include <stdint.h>

#define TCL_V643_MCAST_HELPER_MAGIC UINT32_C(0x544d4348) /* TMCH */
#define TCL_V643_MCAST_HELPER_VERSION UINT32_C(1)

/* Fixed-width wire layout for the future AArch64 coordinator/AArch32 waiter
 * boundary.  Kernel addresses must never be represented as uintptr_t on the
 * helper side.  Version 1 defines only a non-arming self-test handshake. */
struct tcl_v643_mcast_helper_message {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t flags;
  uint64_t fake_task;
  uint64_t fake_lock;
  uint32_t wake_state;
  int32_t prio;
};

_Static_assert(sizeof(struct tcl_v643_mcast_helper_message) == 40,
               "MCAST helper protocol layout changed");

#endif
