#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/devices/tcl_v643/capture_witness.h"

int main(void) {
  uint64_t pfn = 0;
  assert(!tcl_pagemap_decode_pfn(0, 2, &pfn));
  assert(!tcl_pagemap_decode_pfn(TCL_PAGEMAP_PRESENT, 2, &pfn));
  assert(!tcl_pagemap_decode_pfn(
      TCL_PAGEMAP_PRESENT | TCL_PAGEMAP_SWAPPED | 0x1234, 2, &pfn));
  assert(tcl_pagemap_decode_pfn(TCL_PAGEMAP_PRESENT | 0x1237, 2, &pfn));
  assert(pfn == 0x1234);

  assert(tcl_target_head_pfn(UINT64_C(0xffffff805b5a4000),
                             UINT64_C(0xffffff8000000000),
                             UINT64_C(0x20000000), 2) == UINT64_C(0x7b5a4));
  assert(tcl_target_head_pfn(0x1000, 0x2000, 0, 2) == UINT64_MAX);

  assert(tcl_capture_verdict(16, 0, 0) == TCL_CAPTURE_UNAVAILABLE);
  assert(tcl_capture_verdict(16, 15, 1) == TCL_CAPTURE_UNAVAILABLE);
  assert(tcl_capture_verdict(16, 16, 0) == TCL_CAPTURE_MISMATCH);
  assert(tcl_capture_verdict(16, 16, 1) == TCL_CAPTURE_CONFIRMED);
  assert(tcl_capture_verdict(16, 16, 2) == TCL_CAPTURE_AMBIGUOUS);
  assert(!tcl_capture_may_arm(TCL_CAPTURE_UNAVAILABLE, -1));
  assert(!tcl_capture_may_arm(TCL_CAPTURE_MISMATCH, -1));
  assert(!tcl_capture_may_arm(TCL_CAPTURE_AMBIGUOUS, -1));
  assert(!tcl_capture_may_arm(TCL_CAPTURE_CONFIRMED, -1));
  assert(tcl_capture_may_arm(TCL_CAPTURE_CONFIRMED, 0));
  puts("PASS: TCL V643 capture witness is fail-closed for masked, missing and ambiguous PFNs");
  return 0;
}
