#ifndef TCL_V643_PSELECT_CARRIER_H
#define TCL_V643_PSELECT_CARRIER_H

#include <stdint.h>
#include <string.h>

#include "stack_geometry.h"

/*
 * User-side input image consumed by core_sys_select() on the exact V643
 * kernel.  Only the first 40 bytes of each fd_set are copied for nfds=320.
 * The kernel lays the three input sets consecutively in stack_fds, followed
 * by three zeroed output sets.  stack_fds+0x30 therefore aliases the stale
 * rt_mutex_waiter recovered from the preceding futex syscall.
 *
 * This constructor only packs bytes.  It does not make a syscall and is also
 * used by host-only tests.
 */
struct tcl_v643_pselect_carrier {
  uint8_t readfds[TCL_V643_FDSET_BYTES];
  uint8_t writefds[TCL_V643_FDSET_BYTES];
  uint8_t exceptfds[TCL_V643_FDSET_BYTES];
};

static inline void tcl_v643_build_pselect_carrier(
    struct tcl_v643_pselect_carrier *carrier,
    uint64_t task, uint64_t lock, uint32_t wake_state, int32_t prio) {
  uint64_t wake_prio = (uint64_t)wake_state | ((uint64_t)(uint32_t)prio << 32);

  memset(carrier, 0, sizeof(*carrier));

  /* waiter.pi_tree.rb_right/rb_left are in exceptfds +0/+8 and remain 0.
   * The tree and remaining pi_tree words are in writefds and remain 0. */
  memcpy(carrier->exceptfds + 0x10, &task, sizeof(task));
  memcpy(carrier->exceptfds + 0x18, &lock, sizeof(lock));
  memcpy(carrier->exceptfds + 0x20, &wake_prio, sizeof(wake_prio));
}

static inline int tcl_v643_carrier_fd_selected(
    const struct tcl_v643_pselect_carrier *carrier, unsigned fd) {
  const uint8_t *sets[] = {
      carrier->readfds, carrier->writefds, carrier->exceptfds,
  };
  unsigned byte = fd / 8;
  uint8_t mask = (uint8_t)(1U << (fd % 8));

  if (fd >= TCL_V643_PSELECT_NFDS) return 0;
  return !!((sets[0][byte] | sets[1][byte] | sets[2][byte]) & mask);
}

#endif
