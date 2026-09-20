#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tcl_v643/compat_select_geometry.h"
#include "tcl_v643/stack_geometry.h"

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

int main(void) {
  const int bitmap_rel =
      -TCL_V643_COMPAT_SELECT_WRAPPER_FRAME -
      TCL_V643_DO_COMPAT_SELECT_FRAME -
      TCL_V643_COMPAT_CORE_SELECT_FRAME +
      TCL_V643_COMPAT_CORE_BITMAP_OFF;
  const int waiter_rel = TCL_V643_COMPAT_FUTEX_WAITER_REL;
  const int waiter_in_bitmaps = waiter_rel - bitmap_rel;

  if (bitmap_rel != TCL_V643_COMPAT_SELECT_BITMAP_REL)
    return fail("compat-select bitmap coordinate changed");
  if (waiter_in_bitmaps != TCL_V643_COMPAT_WAITER_IN_BITMAPS)
    return fail("compat-select no longer aliases the stale waiter at +0x30");
  if (TCL_V643_COMPAT_SELECT_SET_BYTES * 3 !=
      TCL_V643_COMPAT_SELECT_INPUT_BYTES)
    return fail("input bitmap length mismatch");
  if (TCL_V643_COMPAT_SELECT_SET_BYTES * 6 !=
      TCL_V643_COMPAT_SELECT_ALL_BYTES)
    return fail("complete bitmap length mismatch");

  const unsigned task = TCL_V643_COMPAT_WAITER_IN_BITMAPS +
                        TCL_V643_WAITER_TASK;
  const unsigned lock = TCL_V643_COMPAT_WAITER_IN_BITMAPS +
                        TCL_V643_WAITER_LOCK;
  const unsigned wake_state = TCL_V643_COMPAT_WAITER_IN_BITMAPS +
                              TCL_V643_WAITER_WAKE_STATE;
  const unsigned prio = TCL_V643_COMPAT_WAITER_IN_BITMAPS +
                        TCL_V643_WAITER_PRIO;
  const unsigned deadline = TCL_V643_COMPAT_WAITER_IN_BITMAPS +
                            TCL_V643_WAITER_DEADLINE;
  const unsigned ww_ctx = TCL_V643_COMPAT_WAITER_IN_BITMAPS +
                          TCL_V643_WAITER_WW_CTX;

  if (task != 0x60 || lock != 0x68 || wake_state != 0x70 || prio != 0x74)
    return fail("critical waiter fields are not in the copied input bitmaps");
  if (prio + sizeof(uint32_t) != TCL_V643_COMPAT_SELECT_INPUT_BYTES)
    return fail("input boundary does not end exactly after waiter.prio");
  if (deadline != TCL_V643_COMPAT_SELECT_INPUT_BYTES || ww_ctx != 0x80)
    return fail("deadline/ww_ctx do not begin in the zeroed output bitmaps");
  if (TCL_V643_COMPAT_WAITER_IN_BITMAPS + TCL_V643_WAITER_SIZE >
      TCL_V643_COMPAT_SELECT_ALL_BYTES)
    return fail("the complete waiter is not covered by the bitmap block");

  uint8_t bitmaps[TCL_V643_COMPAT_SELECT_ALL_BYTES];
  memset(bitmaps, 0xa5, TCL_V643_COMPAT_SELECT_INPUT_BYTES);
  memset(bitmaps + TCL_V643_COMPAT_SELECT_INPUT_BYTES, 0,
         sizeof(bitmaps) - TCL_V643_COMPAT_SELECT_INPUT_BYTES);

  uint64_t task_value = 0xffffffc00bad1000ULL;
  uint64_t lock_value = 0xffffffc00bad2000ULL;
  uint32_t wake_value = 3;
  int32_t prio_value = 140;
  memcpy(bitmaps + task, &task_value, sizeof(task_value));
  memcpy(bitmaps + lock, &lock_value, sizeof(lock_value));
  memcpy(bitmaps + wake_state, &wake_value, sizeof(wake_value));
  memcpy(bitmaps + prio, &prio_value, sizeof(prio_value));

  uint64_t got_task = 0, got_lock = 0, got_deadline = 1, got_ww_ctx = 1;
  uint32_t got_wake = 0;
  int32_t got_prio = 0;
  memcpy(&got_task, bitmaps + task, sizeof(got_task));
  memcpy(&got_lock, bitmaps + lock, sizeof(got_lock));
  memcpy(&got_wake, bitmaps + wake_state, sizeof(got_wake));
  memcpy(&got_prio, bitmaps + prio, sizeof(got_prio));
  memcpy(&got_deadline, bitmaps + deadline, sizeof(got_deadline));
  memcpy(&got_ww_ctx, bitmaps + ww_ctx, sizeof(got_ww_ctx));

  if (got_task != task_value || got_lock != lock_value ||
      got_wake != wake_value || got_prio != prio_value)
    return fail("controlled compat-select waiter fields do not round-trip");
  if (got_deadline != 0 || got_ww_ctx != 0)
    return fail("output bitmaps do not zero the waiter tail");

  printf("compat syscall_sp: bitmaps=-%#x waiter=-%#x delta=+%#x\n",
         -bitmap_rel, -waiter_rel, waiter_in_bitmaps);
  printf("input boundary: task=%#x lock=%#x wake=%#x prio=%#x "
         "deadline=%#x ww_ctx=%#x\n",
         task, lock, wake_state, prio, deadline, ww_ctx);
  puts("PASS: exact V643 ARM32 compat select covers the stale waiter without heap reclaim");
  return 0;
}
