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
    if (strcmp(known_offsets[i].uname_r, "5.15.180-android14-11") == 0) {
      active_offsets = &known_offsets[i];
      break;
    }
  }
  failed |= require(active_offsets != NULL, "V643 profile missing");
  if (!active_offsets) return 1;

  failed |= require(active_offsets->reclaim_route ==
                        GHOST_RECLAIM_TCL_V643_EXACT,
                    "effective TCL exact reclaim route is not selected");
  failed |= require(active_offsets->slub_min_partial == 5 &&
                    active_offsets->slub_cpu_partial == 6,
                    "effective TCL SLUB thresholds are not exact V643 values");

  failed |= require(P0_PAGE_OFFSET == UINT64_C(0xffffff8000000000),
                    "effective PAGE_OFFSET is not V643");
  failed |= require(DIRECT_MAP_BASE == UINT64_C(0xffffff8000000000) &&
                    DIRECT_MAP_END == UINT64_C(0xffffff80c0000000),
                    "effective direct-map span is not V643");
  failed |= require(VMEMMAP_START == UINT64_C(0xfffffffe00000000),
                    "effective VMEMMAP_START is not V643");
  failed |= require(MM_STRUCT_SZ == 1024 && MM_ORDER == 2,
                    "effective mm_struct slab geometry is not V643");

  failed |= require(FAKE_TASK_USAGE_OFF == 0x38 &&
                    FAKE_TASK_CPU_OFF == 0x58 &&
                    FAKE_TASK_UCLAMP_REQ_OFF == 0x348,
                    "effective task_struct offsets are not V643");
  failed |= require(FAKE_WAITER_PI_TREE_ENTRY_OFF == 0x18 &&
                    FAKE_WAITER_TASK_OFF == 0x30 &&
                    FAKE_WAITER_PRIO_OFF == 0x44 &&
                    RT_MUTEX_OWNER_OFF == 0x18,
                    "effective waiter/rt_mutex offsets are not V643");

  failed |= require(CRED15_SIZE == 0xb0 && CRED15_UID_OFF == 0x04 &&
                    CRED15_CAP_EFF_OFF == 0x38 &&
                    CRED15_USER_NS_OFF == 0x88,
                    "effective cred layout is not V643");
  failed |= require(USER_STRUCT_SIZE == 0xa8 && UCOUNTS_SIZE == 0x90 &&
                    USER_NS_SIZE == 0x290 &&
                    USER_NS_GID_MAP_OFF == 0x48 &&
                    USER_NS_UCOUNT_MAX_OFF == 0x210,
                    "effective supporting-object layouts are not V643");
  failed |= require(FAKE_USER_STRUCT_OFF + USER_STRUCT_SIZE <=
                        FAKE_UCOUNTS_OFF,
                    "effective fake user_struct overlaps fake ucounts");
  failed |= require(FAKE_GROUP_INFO_OFF + 0x48 <= FAKE_CRED_OFF,
                    "effective fake group_info overlaps fake cred");
  failed |= require(FAKE_CRED_OFF + CRED15_SIZE <= FAKE_SEC_BLOB_OFF,
                    "effective fake cred overlaps fake task security");
  failed |= require(FAKE_SEC_BLOB_OFF + TASK_SECURITY_SIZE <=
                        FAKE_USER_STRUCT_OFF,
                    "effective fake task security overlaps fake user_struct");
  failed |= require(FAKE_UCOUNTS_OFF + UCOUNTS_SIZE <= FAKE_USER_NS_OFF,
                    "effective fake ucounts overlaps fake user_namespace");
  failed |= require(FAKE_USER_NS_OFF + USER_NS_SIZE < (4096U << MM_ORDER),
                    "effective fake user_namespace exceeds the order-2 slab");

  if (failed) return 1;
  puts("PASS: effective TCL V643 runtime macros are profile-derived");
  return 0;
}
