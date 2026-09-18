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
                        GHOST_STACK_OVERLAY_TCL_V643_PSELECT6,
                    "TCL V643 must select its pselect6 carrier");
  failed |= require(tcl->analysis_blocker != NULL &&
                    strstr(tcl->analysis_blocker, "not dynamically proven") != NULL,
                    "analysis-only profile must state its blocker");
  failed |= require(tcl->kernel_phys_load == 0,
                    "unproven kernel physical load must stay unset");
  failed |= require(tcl->phys_offset == 0x20000000ULL,
                    "TCL DRAM physical base changed unexpectedly");
  failed |= require(tcl->kimage_text_base == 0xffffffc008000000ULL,
                    "TCL link-time text base changed unexpectedly");
  failed |= require(tcl->task_pi_blocked_on == 0x910,
                    "task_struct BTF offset changed unexpectedly");
  failed |= require(tcl->waiter_pi_tree == 0x18 &&
                    tcl->waiter_task == 0x30 &&
                    tcl->waiter_lock == 0x38,
                    "rt_mutex_waiter BTF offsets changed unexpectedly");
  failed |= require(tcl->struct_slab_cache == 0x18,
                    "struct page slab_cache BTF offset changed unexpectedly");

  if (failed) return 1;
  puts("PASS: TCL V643 profile is present and safely analysis-only");
  return 0;
}
