#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "offsets.h"

static int require(int condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

int main(void) {
  const struct kernel_offsets *tcl = NULL;
  int matches = 0;

  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(known_offsets[i].uname_r, "5.15.180-android14-11") == 0) {
      tcl = &known_offsets[i];
      matches++;
    }
  }

  int failed = 0;
  failed |= require(matches == 1, "TCL V643 profile must occur exactly once");
  failed |= require(tcl != NULL, "TCL V643 profile is missing");
  if (!tcl) return 1;

  failed |= require(tcl->analysis_only == 1,
                    "TCL V643 profile must remain analysis-only");
  failed |= require(tcl->stack_overlay_route ==
                        GHOST_STACK_OVERLAY_TCL_V643_NEWSELECT_COMPAT,
                    "TCL V643 must select its persistent ARM32 _newselect carrier");
  failed |= require(tcl->reclaim_route == GHOST_RECLAIM_TCL_V643_EXACT,
                    "TCL V643 must select the exact reclaim route");
  failed |= require(tcl->analysis_blocker != NULL &&
                    strstr(tcl->analysis_blocker, "PFN witness") != NULL,
                    "analysis-only profile must state its blocker");
  failed |= require(tcl->kernel_phys_load == 0x26000000ULL,
                    "proven TCL physical text load changed unexpectedly");
  failed |= require(tcl->phys_offset == 0x20000000ULL,
                    "TCL DRAM physical base changed unexpectedly");
  failed |= require(tcl->page_offset == 0xffffff8000000000ULL,
                    "TCL linear-map base changed unexpectedly");
  failed |= require(tcl->direct_map_base == 0xffffff8000000000ULL &&
                    tcl->direct_map_end == 0xffffff80c0000000ULL,
                    "TCL live direct-map span changed unexpectedly");
  failed |= require(tcl->vmemmap_start == 0xfffffffe00000000ULL,
                    "TCL vmemmap base changed unexpectedly");
  failed |= require(tcl->kernelsnitch_identity_start ==
                        tcl->direct_map_base &&
                    tcl->kernelsnitch_identity_end == tcl->direct_map_end,
                    "KernelSnitch scan must match TCL live RAM aliases");
  failed |= require(tcl->mm_struct_size == 1024 && tcl->mm_slab_order == 2,
                    "TCL mm_struct slab geometry changed unexpectedly");
  failed |= require(tcl->slub_min_partial == 5 &&
                    tcl->slub_cpu_partial == 6,
                    "TCL exact SLUB partial thresholds changed unexpectedly");
  failed |= require(tcl->kimage_text_base == 0xffffffc008000000ULL,
                    "TCL link-time text base changed unexpectedly");
  failed |= require(tcl->task_pi_blocked_on == 0x910,
                    "task_struct BTF offset changed unexpectedly");
  failed |= require(tcl->task_usage == 0x38 && tcl->task_cpu == 0x58 &&
                    tcl->task_uclamp_req == 0x348 &&
                    tcl->task_uclamp == 0x350,
                    "TCL task usage/cpu/uclamp BTF offsets changed unexpectedly");
  failed |= require(tcl->waiter_pi_tree == 0x18 &&
                    tcl->waiter_task == 0x30 &&
                    tcl->waiter_lock == 0x38,
                    "rt_mutex_waiter BTF offsets changed unexpectedly");
  failed |= require(tcl->waiter_size == 0x58 &&
                    tcl->waiter_prio == 0x44 &&
                    tcl->waiter_deadline == 0x48 &&
                    tcl->rt_mutex_size == 0x20 &&
                    tcl->rt_mutex_waiters == 0x08 &&
                    tcl->rt_mutex_owner == 0x18,
                    "TCL waiter/rt_mutex BTF layout changed unexpectedly");
  failed |= require(tcl->struct_slab_cache == 0x18,
                    "struct page slab_cache BTF offset changed unexpectedly");
  failed |= require(tcl->cred_size == 0xb0 &&
                    tcl->cred_uid == 0x04 &&
                    tcl->cred_cap_eff == 0x38 &&
                    tcl->cred_security == 0x78 &&
                    tcl->cred_user_ns == 0x88 &&
                    tcl->cred_group_info == 0x98,
                    "TCL struct cred BTF layout changed unexpectedly");
  failed |= require(tcl->task_security_size == 0x18 &&
                    tcl->user_struct_size == 0xa8 &&
                    tcl->ucounts_size == 0x90 &&
                    tcl->group_info_gid == 0x08 &&
                    tcl->user_ns_size == 0x290 &&
                    tcl->user_ns_gid_map == 0x48 &&
                    tcl->user_ns_projid_map == 0x90 &&
                    tcl->user_ns_ucount_max == 0x210 &&
                    tcl->user_ns_ucount_max_count == 14 &&
                    tcl->uid_gid_map_extent == 0x08,
                    "TCL fake-cred support layouts changed unexpectedly");
  failed |= require(tcl->payload_fake_user + tcl->user_struct_size <=
                        tcl->payload_fake_ucounts,
                    "TCL fake user_struct overlaps fake ucounts");
  failed |= require(tcl->payload_fake_group_info + 0x48 <=
                        tcl->payload_fake_cred,
                    "TCL fake group_info overlaps fake cred");
  failed |= require(tcl->payload_fake_cred + tcl->cred_size <=
                        tcl->payload_fake_security,
                    "TCL fake cred overlaps fake task security");
  failed |= require(tcl->payload_fake_security + tcl->task_security_size <=
                        tcl->payload_fake_user,
                    "TCL fake task security overlaps fake user_struct");
  failed |= require(tcl->payload_fake_ucounts + tcl->ucounts_size <=
                        tcl->payload_fake_user_ns,
                    "TCL fake ucounts overlaps fake user_namespace");
  failed |= require(tcl->payload_fake_user_ns + tcl->user_ns_size <
                        (4096U << tcl->mm_slab_order),
                    "TCL fake user_namespace exceeds the order-2 slab");

  if (failed) return 1;
  puts("PASS: TCL V643 profile is present and safely analysis-only");
  return 0;
}
