#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/devices/tcl_v643/io_uring_perf_witness.h"

int main(void) {
  const uint64_t anchor = UINT64_C(0xffffffc003400000);
  const uint64_t target = UINT64_C(0xffffff8058434000);
  uint64_t regs[31] = {0};

  regs[TCL_V643_PERF_RING_REG] = target;
  assert(tcl_v643_perf_ring_sample(
      anchor + TCL_V643_PERF_RING_IP_OFF, regs, anchor, target,
      TCL_V643_PERF_RING_IP_OFF, TCL_V643_PERF_RING_IP_LAST_OFF,
      TCL_V643_PERF_RING_REG));
  assert(tcl_v643_perf_ring_sample(
      anchor + TCL_V643_PERF_RING_IP_LAST_OFF, regs, anchor, target,
      TCL_V643_PERF_RING_IP_OFF, TCL_V643_PERF_RING_IP_LAST_OFF,
      TCL_V643_PERF_RING_REG));
  assert(!tcl_v643_perf_ring_sample(
      anchor + TCL_V643_PERF_RING_IP_OFF + 4, regs, anchor, target,
      TCL_V643_PERF_RING_IP_OFF, TCL_V643_PERF_RING_IP_OFF,
      TCL_V643_PERF_RING_REG));
  regs[TCL_V643_PERF_RING_REG] = target + 8;
  assert(!tcl_v643_perf_ring_sample(
      anchor + TCL_V643_PERF_RING_IP_OFF, regs, anchor, target,
      TCL_V643_PERF_RING_IP_OFF, TCL_V643_PERF_RING_IP_LAST_OFF,
      TCL_V643_PERF_RING_REG));

  for (int i = 0; i < 31; i++) regs[i] = 0;
  regs[TCL_V643_PERF_SQE_REG] = target;
  assert(tcl_v643_perf_sqe_sample(
      anchor + TCL_V643_PERF_SQE_IP_OFF, regs, anchor, target,
      TCL_V643_PERF_SQE_IP_OFF, TCL_V643_PERF_SQE_IP_LAST_OFF,
      TCL_V643_PERF_SQE_REG));
  regs[TCL_V643_PERF_SQE_REG] = target + 0x4000;
  assert(!tcl_v643_perf_sqe_sample(
      anchor + TCL_V643_PERF_SQE_IP_OFF, regs, anchor, target,
      TCL_V643_PERF_SQE_IP_OFF, TCL_V643_PERF_SQE_IP_LAST_OFF,
      TCL_V643_PERF_SQE_REG));
  regs[TCL_V643_PERF_SQE_REG] = target;
  assert(!tcl_v643_perf_sqe_sample(
      anchor + TCL_V643_PERF_SQE_IP_OFF - 4, regs, anchor, target,
      TCL_V643_PERF_SQE_IP_OFF, TCL_V643_PERF_SQE_IP_LAST_OFF,
      TCL_V643_PERF_SQE_REG));

  /* A matching target-shaped pointer at an unrelated IP must never count. */
  assert(!tcl_v643_perf_ring_sample(anchor + 0x1234, regs, anchor, target,
                                    TCL_V643_PERF_RING_IP_OFF,
                                    TCL_V643_PERF_RING_IP_LAST_OFF,
                                    TCL_V643_PERF_RING_REG));
  assert(!tcl_v643_perf_sqe_sample(anchor + 0x5678, regs, anchor, target,
                                   TCL_V643_PERF_SQE_IP_OFF,
                                   TCL_V643_PERF_SQE_IP_LAST_OFF,
                                   TCL_V643_PERF_SQE_REG));

  /* The QEMU cross-check kernel uses x2 at its exact SQE semantic site.
   * Register selection is explicit so a device/QEMU offset cannot silently
   * inherit the wrong register contract. */
  for (int i = 0; i < 31; i++) regs[i] = 0;
  regs[2] = target;
  assert(tcl_v643_perf_sqe_sample(anchor + 0x00938ad8, regs, anchor,
                                  target, 0x00938ad8, 0x00938ae8, 2));
  assert(!tcl_v643_perf_sqe_sample(anchor + 0x00938ad8, regs, anchor,
                                   target, 0x00938ad8, 0x00938ae8, 8));

  puts("PASS: exact V643 perf witness accepts only semantic rings/SQE register sites");
  return 0;
}
