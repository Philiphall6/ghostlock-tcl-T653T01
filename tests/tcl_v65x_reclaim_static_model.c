#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "offsets.h"
#include "tcl_v65x/io_uring_geometry.h"

static int require(bool condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

static unsigned get_order(unsigned bytes) {
  unsigned pages = (bytes + 4095U) >> 12;
  unsigned order = 0;
  unsigned capacity = 1;
  while (capacity < pages) {
    capacity <<= 1;
    order++;
  }
  return order;
}

int main(void) {
  const struct kernel_offsets *v65x = NULL;
  int failed = 0;

  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(known_offsets[i].uname_r,
               "5.15.192-android14-11") == 0) {
      v65x = &known_offsets[i];
      break;
    }
  }

  failed |= require(v65x != NULL, "T653T01 V65x profile missing");
  if (!v65x) return 1;

  failed |= require(v65x->analysis_only == 1,
                    "V65x profile must remain analysis-only");
  failed |= require(v65x->reclaim_route ==
                        GHOST_RECLAIM_TCL_V65X_UNPROVEN,
                    "V65x live reclaim route must remain unproven");
  failed |= require(v65x->mm_struct_size == 1024 &&
                    v65x->mm_slab_order == 2,
                    "unexpected V65x mm_struct slab geometry");
  failed |= require(v65x->slub_min_partial == 5 &&
                    v65x->slub_cpu_partial == 6,
                    "unexpected V65x SLUB thresholds");

  failed |= require(TCL_V65X_IO_URING_ENTRIES == 256 &&
                    TCL_V65X_IO_URING_CQ_ENTRIES == 512,
                    "unexpected V65x io_uring entry geometry");
  failed |= require(get_order(TCL_V65X_IO_URING_RINGS_BYTES) == 2 &&
                    get_order(TCL_V65X_IO_URING_SQES_BYTES) == 2,
                    "V65x io_uring backing allocations must be order 2");
  failed |= require(TCL_V65X_IO_URING_MAP_BYTES ==
                        (4096U << TCL_V65X_IO_URING_RINGS_ORDER),
                    "unexpected V65x mapping size");
  failed |= require((TCL_V65X_IO_URING_GFP &
                    (TCL_V65X_GFP_MOVABLE |
                     TCL_V65X_GFP_RECLAIMABLE)) == 0,
                    "V65x io_uring GFP changed migratetype");
  failed |= require((TCL_V65X_MM_STRUCT_GFP &
                    (TCL_V65X_GFP_MOVABLE |
                     TCL_V65X_GFP_RECLAIMABLE)) == 0,
                    "V65x mm_struct GFP changed migratetype");
  failed |= require((TCL_V65X_IO_URING_GFP &
                     TCL_V65X_GFP_ZONE_BITS_MASK) == 0 &&
                    (TCL_V65X_MM_STRUCT_GFP &
                     TCL_V65X_GFP_ZONE_BITS_MASK) == 0,
                    "V65x GFP zone bits changed");
  failed |= require(TCL_V65X_PCP_LIST_INDEX(
                        2, TCL_V65X_MIGRATE_UNMOVABLE) == 8,
                    "V65x PCP list index formula changed");
  failed |= require(TCL_V65X_PAGEBLOCK_ORDER == 10 &&
                    TCL_V65X_PAGEBLOCK_PAGES == 1024 &&
                    TCL_V65X_PAGEBLOCK_RETAG_THRESHOLD == 512,
                    "V65x exact pageblock geometry changed");

  /* This assertion is intentional.  Passing the static model must never be
   * confused with authorizing the live reclaim choreography. */
  failed |= require(TCL_V65X_LIVE_PCP_CHOREOGRAPHY_VALIDATED == 0,
                    "static test must not authorize V65x live PCP use");

  if (failed) return 1;
  puts("PASS: T653T01 V65x static reclaim geometry; "
       "live PCP choreography remains REFUSED");
  return 0;
}
