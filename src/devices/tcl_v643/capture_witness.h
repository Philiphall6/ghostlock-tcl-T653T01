#ifndef TCL_V643_CAPTURE_WITNESS_H
#define TCL_V643_CAPTURE_WITNESS_H

#include <stdint.h>

/* Linux pagemap ABI.  Since Linux 4.2 the PFN is zeroed for callers that do
 * not have CAP_SYS_ADMIN.  A zero PFN is therefore UNKNOWN, never evidence
 * that a userspace mapping does not own the target page. */
#define TCL_PAGEMAP_PRESENT (UINT64_C(1) << 63)
#define TCL_PAGEMAP_SWAPPED (UINT64_C(1) << 62)
#define TCL_PAGEMAP_PFN_MASK ((UINT64_C(1) << 55) - 1)

enum tcl_capture_verdict {
  TCL_CAPTURE_UNAVAILABLE = 0,
  TCL_CAPTURE_CONFIRMED = 1,
  TCL_CAPTURE_MISMATCH = -1,
  TCL_CAPTURE_AMBIGUOUS = -2,
};

static inline uint64_t tcl_target_head_pfn(uint64_t slab_kva,
                                           uint64_t page_offset,
                                           uint64_t phys_offset,
                                           unsigned order) {
  if (slab_kva < page_offset || order >= 63)
    return UINT64_MAX;
  uint64_t pfn = (slab_kva - page_offset + phys_offset) >> 12;
  return pfn & ~((UINT64_C(1) << order) - 1);
}

static inline int tcl_pagemap_decode_pfn(uint64_t entry, unsigned order,
                                         uint64_t *head_pfn) {
  if (!(entry & TCL_PAGEMAP_PRESENT) || (entry & TCL_PAGEMAP_SWAPPED))
    return 0;
  uint64_t pfn = entry & TCL_PAGEMAP_PFN_MASK;
  if (!pfn)
    return 0;
  *head_pfn = pfn & ~((UINT64_C(1) << order) - 1);
  return 1;
}

static inline int tcl_capture_verdict(unsigned total_blocks,
                                      unsigned visible_pfns,
                                      unsigned target_hits) {
  if (!total_blocks || visible_pfns != total_blocks)
    return TCL_CAPTURE_UNAVAILABLE;
  if (target_hits == 1)
    return TCL_CAPTURE_CONFIRMED;
  if (target_hits > 1)
    return TCL_CAPTURE_AMBIGUOUS;
  return TCL_CAPTURE_MISMATCH;
}

static inline int tcl_capture_may_arm(int verdict, int block) {
  return verdict == TCL_CAPTURE_CONFIRMED && block >= 0;
}

#endif
