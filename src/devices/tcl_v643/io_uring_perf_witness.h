#ifndef TCL_V643_IO_URING_PERF_WITNESS_H
#define TCL_V643_IO_URING_PERF_WITNESS_H

#include <stdint.h>

/* Exact V643 device-vmlinux instructions, relative to the canonical image
 * _text alias reported by perf.  On the TCL this instruction alias remains
 * at kimage_text_base while data symbols use the separate KASLR anchor.
 * Throughout the mmap site x0 is exactly ctx->rings or ctx->sq_sqes,
 * selected by the mmap offset.  These semantics were checked against the
 * exact
 * vmlinux-v643.elf disassembly, not inferred from source alone. */
#define TCL_V643_PERF_RING_IP_OFF UINT64_C(0x008c9128)
#define TCL_V643_PERF_RING_IP_LAST_OFF UINT64_C(0x008c91ac)
#define TCL_V643_PERF_RING_REG 0
#define TCL_V643_PERF_SQE_IP_OFF UINT64_C(0x008c9128)
#define TCL_V643_PERF_SQE_IP_LAST_OFF UINT64_C(0x008c91ac)
#define TCL_V643_PERF_SQE_REG 0
#define TCL_V643_PERF_MIN_HITS 3

static inline uint64_t tcl_v643_order2_base(uint64_t p) {
  return p & ~UINT64_C(0x3fff);
}

static inline int tcl_v643_perf_ring_sample(uint64_t ip,
                                            const uint64_t regs[31],
                                            uint64_t anchor,
                                            uint64_t target,
                                            uint64_t ring_ip_off,
                                            uint64_t ring_ip_last_off,
                                            unsigned ring_reg) {
  return ip >= anchor + ring_ip_off && ip <= anchor + ring_ip_last_off &&
         !(ip & UINT64_C(3)) &&
         ring_reg < 31 && regs[ring_reg] == target;
}

static inline int tcl_v643_perf_sqe_sample(uint64_t ip,
                                           const uint64_t regs[31],
                                           uint64_t anchor,
                                           uint64_t target,
                                           uint64_t sqe_ip_off,
                                           uint64_t sqe_ip_last_off,
                                           unsigned sqe_reg) {
  if (sqe_reg >= 31) return 0;
  uint64_t p = regs[sqe_reg];
  return ip >= anchor + sqe_ip_off && ip <= anchor + sqe_ip_last_off &&
         !(ip & UINT64_C(3)) && p == target;
}

#endif
