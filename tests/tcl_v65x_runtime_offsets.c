#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "target.h"
#include "offsets.h"

const struct kernel_offsets *active_offsets;

#include "runtime_struct_offsets.h"

static int require(int condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

int main(void) {
  int failed = 0;

  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(known_offsets[i].uname_r, "5.15.192-android14-11") == 0) {
      active_offsets = &known_offsets[i];
      break;
    }
  }
  failed |= require(active_offsets != NULL, "T653T01 V65x profile missing");
  if (!active_offsets) return 1;

  failed |= require(active_offsets->analysis_only == 1,
                    "V65x must remain analysis-only");
  failed |= require(active_offsets->reclaim_route ==
                        GHOST_RECLAIM_TCL_V65X_UNPROVEN,
                    "V65x must retain the unproved reclaim state");
  failed |= require(!ghost_reclaim_is_tcl_exact(
                        active_offsets->reclaim_route),
                    "unproved V65x reclaim was classified executable");
  failed |= require(ghost_reclaim_is_tcl_exact(
                        GHOST_RECLAIM_TCL_V65X_EXACT),
                    "reserved V65x exact route is not wired");
  failed |= require(ghost_stack_overlay_is_tcl_newselect(
                        active_offsets->stack_overlay_route),
                    "V65x did not select the shared ARM32 _newselect route");

  failed |= require(P0_PAGE_OFFSET == UINT64_C(0xffffff8000000000),
                    "effective PAGE_OFFSET is not V65x");
  failed |= require(DIRECT_MAP_BASE == UINT64_C(0xffffff8000000000) &&
                    DIRECT_MAP_END == UINT64_C(0xffffff80c0000000),
                    "effective direct-map span is not V65x");
  failed |= require(VMEMMAP_START == UINT64_C(0xfffffffe00000000),
                    "effective VMEMMAP_START is not V65x");
  failed |= require(MM_STRUCT_SZ == 1024 && MM_ORDER == 2,
                    "effective mm_struct geometry is not V65x");

  failed |= require(FAKE_TASK_USAGE_OFF == 0x38 &&
                    FAKE_TASK_CPU_OFF == 0x58 &&
                    FAKE_TASK_UCLAMP_REQ_OFF == 0x348,
                    "effective task_struct offsets are not V65x");
  failed |= require(FAKE_WAITER_PI_TREE_ENTRY_OFF == 0x18 &&
                    FAKE_WAITER_TASK_OFF == 0x30 &&
                    FAKE_WAITER_LOCK_OFF == 0x38 &&
                    FAKE_WAITER_PRIO_OFF == 0x44 &&
                    RT_MUTEX_OWNER_OFF == 0x18,
                    "effective waiter/rt_mutex offsets are not V65x");
  failed |= require(STRUCT_SLAB_CACHE_OFF == 0x18,
                    "effective nested-BTF slab_cache offset is not V65x");

  failed |= require(CRED15_SIZE == 0xb0 && CRED15_UID_OFF == 0x04 &&
                    CRED15_CAP_EFF_OFF == 0x38 &&
                    CRED15_USER_NS_OFF == 0x88,
                    "effective cred layout is not V65x");
  failed |= require(active_offsets->kimage_text_base +
                        active_offsets->off_init_user_ns_device ==
                        UINT64_C(0xffffffc00a879c50),
                    "canonical V65x init_user_ns address changed");
  failed |= require(active_offsets->kernel_phys_load == 0x26000000ULL,
                    "proved V65x physical load address changed");

  failed |= require(FAKE_GROUP_INFO_OFF + 0x48 <= FAKE_CRED_OFF,
                    "fake group_info overlaps fake cred");
  failed |= require(FAKE_CRED_OFF + CRED15_SIZE <= FAKE_SEC_BLOB_OFF,
                    "fake cred overlaps fake task security");
  failed |= require(FAKE_SEC_BLOB_OFF + TASK_SECURITY_SIZE <=
                        FAKE_USER_STRUCT_OFF,
                    "fake task security overlaps fake user_struct");
  failed |= require(FAKE_UCOUNTS_OFF + UCOUNTS_SIZE <= FAKE_USER_NS_OFF,
                    "fake ucounts overlaps fake user_namespace");
  failed |= require(FAKE_USER_NS_OFF + USER_NS_SIZE < (4096U << MM_ORDER),
                    "fake user_namespace exceeds the order-2 slab");

  if (failed) return 1;
  puts("PASS: T653T01 V65x runtime offsets and shared _newselect carrier "
       "are integrated; reclaim execution remains REFUSED");
  return 0;
}
