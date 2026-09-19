#include <stdbool.h>
#include <stdio.h>

#include "tcl_v643/io_uring_geometry.h"

#define MODEL_CPUS 2
#define MODEL_ORDERS 4
#define MODEL_TYPES 3
#define MODEL_DEPTH 16

enum page_id {
  PAGE_NONE = 0,
  PAGE_TARGET,
  PAGE_DECOY_A,
  PAGE_DECOY_B,
};

enum direct_route_result {
  ROUTE_DIRECT_CAPTURE = 0,
  ROUTE_DIRECT_MISS,
  ROUTE_BUDDY_UNKNOWN,
  ROUTE_BULK_UNKNOWN,
};

struct direct_route_conditions {
  unsigned free_zone;
  unsigned alloc_zone;
  unsigned free_cpu;
  unsigned alloc_cpu;
  unsigned free_type;
  unsigned alloc_type;
  unsigned old_count;
  unsigned high;
  unsigned newer_exact_list_frees;
  bool free_trylock;
  bool first_alloc_trylock;
  bool second_alloc_trylock;
  bool vendor_bypass;
};

struct pcp_list {
  enum page_id pages[MODEL_DEPTH];
  unsigned count;
};

/* One instance represents one (zone, CPU) PCP pair. */
struct pcp_cpu {
  struct pcp_list lists[MODEL_ORDERS][MODEL_TYPES];
  unsigned count;
  unsigned high;
  bool bulk_path;
};

static int require(bool condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

/* Models the direct-PCP portion of free_unref_page_commit().  The exact
 * kernel adds at the list head, increments pcp->count by 1 << order, and
 * enters free_pcppages_bulk() when the resulting count is >= high.  Once
 * that bulk path is entered, this small model deliberately stops claiming a
 * direct-capture guarantee instead of guessing which PCP list is drained. */
static bool pcp_free(struct pcp_cpu *pcp, unsigned order,
                     unsigned migratetype, enum page_id page) {
  struct pcp_list *list = &pcp->lists[order][migratetype];
  if (list->count >= MODEL_DEPTH) return false;
  for (unsigned i = list->count; i > 0; i--)
    list->pages[i] = list->pages[i - 1];
  list->pages[0] = page;
  list->count++;
  pcp->count += 1U << order;
  if (pcp->count >= pcp->high) {
    pcp->bulk_path = true;
    return false;
  }
  return true;
}

/* get_populated_pcp_list() returns the exact list selected by
 * order/migratetype.  Its caller loads list->next and removes that first
 * entry, so the direct PCP path is LIFO. */
static enum page_id pcp_direct_alloc(struct pcp_cpu *pcp, unsigned order,
                                     unsigned migratetype) {
  struct pcp_list *list = &pcp->lists[order][migratetype];
  if (!list->count) return PAGE_NONE;
  enum page_id page = list->pages[0];
  for (unsigned i = 1; i < list->count; i++)
    list->pages[i - 1] = list->pages[i];
  list->count--;
  pcp->count -= 1U << order;
  return page;
}

/* When the exact list is empty, V643 get_populated_pcp_list() refills it from
 * the buddy allocator.  This helper captures the batch scaling only; the
 * buddy contents/fallback policy are intentionally outside the direct-PCP
 * model. */
static unsigned refill_batch(unsigned batch, unsigned order) {
  if (batch <= 1) return batch;
  unsigned scaled = batch >> order;
  return scaled > 2 ? scaled : 2;
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

/* Both callers request ZONE_NORMAL.  The exact TCL snapshot has no managed
 * NORMAL pages and one NUMA node, so the first usable lower zone is DMA32.
 * This models only that proved V643 topology, not a generic Linux zonelist. */
static unsigned v643_actual_kernel_zone(void) {
  if (TCL_V643_NORMAL_MANAGED_PAGES)
    return TCL_V643_ZONE_NORMAL;
  if (TCL_V643_DMA32_MANAGED_PAGES)
    return TCL_V643_ZONE_DMA32;
  return TCL_V643_ZONE_NONE;
}

/* Qualification matrix for the two-allocation direct-PCP claim.  A trylock
 * failure, vendor diversion or bulk drain does not prove a miss: it hands
 * control to a buddy/bulk path that this deliberately small model treats as
 * unknown.  Two newer exact-list frees are a proved direct miss because the
 * rings and SQE allocations consume only two entries. */
static enum direct_route_result qualify_direct_route(
    const struct direct_route_conditions *c) {
  if (c->free_zone != c->alloc_zone || c->free_cpu != c->alloc_cpu ||
      c->free_type != c->alloc_type)
    return ROUTE_DIRECT_MISS;
  if (!c->free_trylock || c->vendor_bypass)
    return ROUTE_BUDDY_UNKNOWN;
  if (c->old_count + (1U << TCL_V643_IO_URING_RINGS_ORDER) >= c->high)
    return ROUTE_BULK_UNKNOWN;
  if (!c->first_alloc_trylock || !c->second_alloc_trylock)
    return ROUTE_BUDDY_UNKNOWN;
  if (c->newer_exact_list_frees > 1)
    return ROUTE_DIRECT_MISS;
  return ROUTE_DIRECT_CAPTURE;
}

int main(void) {
  int failed = 0;
  const unsigned order = TCL_V643_IO_URING_RINGS_ORDER;
  const unsigned unmovable = TCL_V643_MIGRATE_UNMOVABLE;
  const unsigned movable = TCL_V643_MIGRATE_MOVABLE;

  failed |= require(TCL_V643_IO_URING_ENTRIES == 256 &&
                    TCL_V643_IO_URING_CQ_ENTRIES == 512,
                    "unexpected V643 io_uring entry geometry");
  failed |= require(get_order(TCL_V643_IO_URING_RINGS_BYTES) == 2 &&
                    get_order(TCL_V643_IO_URING_SQES_BYTES) == 2,
                    "both V643 io_uring allocations must be order 2");
  failed |= require(TCL_V643_IO_URING_RINGS_BYTES <=
                        TCL_V643_IO_URING_MAP_BYTES &&
                    TCL_V643_IO_URING_SQES_BYTES <=
                        TCL_V643_IO_URING_MAP_BYTES &&
                    TCL_V643_IO_URING_MAP_BYTES == (4096U << order),
                    "16K mmap must cover both order-2 backing pages");
  failed |= require((TCL_V643_IO_URING_GFP &
                    (TCL_V643_GFP_MOVABLE |
                     TCL_V643_GFP_RECLAIMABLE)) == 0,
                    "io_uring GFP unexpectedly requests a movable type");
  failed |= require((TCL_V643_MM_STRUCT_GFP &
                    (TCL_V643_GFP_MOVABLE |
                     TCL_V643_GFP_RECLAIMABLE)) == 0,
                    "copy_mm GFP unexpectedly requests a movable type");
  failed |= require((TCL_V643_MM_STRUCT_GFP &
                     TCL_V643_GFP_ZONE_BITS_MASK) == 0 &&
                    (TCL_V643_IO_URING_GFP &
                     TCL_V643_GFP_ZONE_BITS_MASK) == 0 &&
                    TCL_V643_REQUESTED_HIGHEST_ZONE ==
                     TCL_V643_ZONE_NORMAL,
                    "V643 callers must request the same highest zone");
  failed |= require(v643_actual_kernel_zone() == TCL_V643_ZONE_DMA32,
                    "empty NORMAL zone must force both callers to DMA32");
  failed |= require(TCL_V643_PCP_LIST_INDEX(2, unmovable) == 8 &&
                    TCL_V643_PCP_LIST_INDEX(2, movable) == 9,
                    "V643 PCP list index formula mismatch");
  failed |= require(refill_batch(63, order) == 15,
                    "V643 snapshot batch must refill 15 order-2 pages");

  /* Archived read-only zoneinfo snapshot: count=1802, high=1928.  With no
   * intervening same-list free, the discarded UNMOVABLE target is the head
   * and the first io_uring allocation takes it. */
  struct pcp_cpu cpus[MODEL_CPUS] = {0};
  cpus[0].count = 1802;
  cpus[0].high = 1928;
  failed |= require(pcp_free(&cpus[0], order, unmovable, PAGE_TARGET),
                    "snapshot margin should avoid the bulk path");
  failed |= require(pcp_direct_alloc(&cpus[0], order, unmovable) == PAGE_TARGET,
                    "first same-CPU order-2 UNMOVABLE allocation missed head");

  /* io_uring_setup(256) performs two consecutive order-2 allocations.  One
   * newer exact-list free can displace the target once, but ring+SQE still
   * consume both head entries. */
  struct pcp_cpu one_interloper = {.count = 100, .high = 256};
  pcp_free(&one_interloper, order, unmovable, PAGE_TARGET);
  pcp_free(&one_interloper, order, unmovable, PAGE_DECOY_A);
  failed |= require(pcp_direct_alloc(&one_interloper, order, unmovable) == PAGE_DECOY_A,
                    "LIFO did not return the newer exact-list page first");
  failed |= require(pcp_direct_alloc(&one_interloper, order, unmovable) == PAGE_TARGET,
                    "second io_uring allocation did not reach target");

  /* Two newer exact-list frees exceed the two-allocation coverage. */
  struct pcp_cpu two_interlopers = {.count = 100, .high = 256};
  pcp_free(&two_interlopers, order, unmovable, PAGE_TARGET);
  pcp_free(&two_interlopers, order, unmovable, PAGE_DECOY_A);
  pcp_free(&two_interlopers, order, unmovable, PAGE_DECOY_B);
  failed |= require(pcp_direct_alloc(&two_interlopers, order, unmovable) != PAGE_TARGET &&
                    pcp_direct_alloc(&two_interlopers, order, unmovable) != PAGE_TARGET,
                    "two newer frees should hide target beyond ring+SQE");

  /* A different PCP migratetype neither displaces nor satisfies the exact
   * UNMOVABLE lookup.  A MOVABLE target therefore has no direct PCP route to
   * this io_uring allocation. */
  struct pcp_cpu cross_type = {.count = 100, .high = 256};
  pcp_free(&cross_type, order, unmovable, PAGE_TARGET);
  pcp_free(&cross_type, order, movable, PAGE_DECOY_A);
  failed |= require(pcp_direct_alloc(&cross_type, order, unmovable) == PAGE_TARGET,
                    "different migratetype displaced exact PCP head");

  struct pcp_cpu movable_target = {.count = 100, .high = 256};
  pcp_free(&movable_target, order, movable, PAGE_TARGET);
  failed |= require(pcp_direct_alloc(&movable_target, order, unmovable) == PAGE_NONE,
                    "UNMOVABLE direct lookup consumed MOVABLE target");

  /* PCPs are per CPU. */
  cpus[0] = (struct pcp_cpu){.count = 100, .high = 256};
  cpus[1] = (struct pcp_cpu){.count = 100, .high = 256};
  pcp_free(&cpus[1], order, unmovable, PAGE_TARGET);
  failed |= require(pcp_direct_alloc(&cpus[0], order, unmovable) == PAGE_NONE,
                    "allocation on another CPU consumed target PCP list");

  /* PCP pagesets are also per zone.  An allocation served from a different
   * zone cannot see the target even on the same CPU. */
  struct pcp_cpu zones[2] = {
    {.count = 100, .high = 256},
    {.count = 100, .high = 256},
  };
  pcp_free(&zones[1], order, unmovable, PAGE_TARGET);
  failed |= require(pcp_direct_alloc(&zones[0], order, unmovable) == PAGE_NONE,
                    "allocation from another zone consumed target PCP list");

  /* At equality the V643 branch enters free_pcppages_bulk().  The direct
   * LIFO proof must stop here because the target can leave the PCP list. */
  struct pcp_cpu at_high = {.count = 1924, .high = 1928};
  failed |= require(!pcp_free(&at_high, order, unmovable, PAGE_TARGET) &&
                    at_high.bulk_path,
                    "count + four equal to high must enter bulk path");

  /* The current implementation pins the orchestrator before copy_mm, the
   * memfd close/task-work free and io_uring setup.  Model that proved same-CPU
   * case separately from the still-dynamic lock/count/interference inputs. */
  struct direct_route_conditions route = {
    .free_zone = v643_actual_kernel_zone(),
    .alloc_zone = v643_actual_kernel_zone(),
    .free_cpu = 0,
    .alloc_cpu = 0,
    .free_type = unmovable,
    .alloc_type = unmovable,
    .old_count = 1802,
    .high = 1928,
    .free_trylock = true,
    .first_alloc_trylock = true,
    .second_alloc_trylock = true,
  };
  failed |= require(qualify_direct_route(&route) == ROUTE_DIRECT_CAPTURE,
                    "qualified same-zone/CPU direct route should capture");
  route.newer_exact_list_frees = 1;
  failed |= require(qualify_direct_route(&route) == ROUTE_DIRECT_CAPTURE,
                    "two io_uring allocations must cover one interloper");
  route.newer_exact_list_frees = 2;
  failed |= require(qualify_direct_route(&route) == ROUTE_DIRECT_MISS,
                    "two interlopers must exceed direct coverage");
  route.newer_exact_list_frees = 0;
  route.free_trylock = false;
  failed |= require(qualify_direct_route(&route) == ROUTE_BUDDY_UNKNOWN,
                    "free trylock failure must terminate direct-PCP proof");
  route.free_trylock = true;
  route.first_alloc_trylock = false;
  failed |= require(qualify_direct_route(&route) == ROUTE_BUDDY_UNKNOWN,
                    "allocation trylock failure must terminate direct proof");
  route.first_alloc_trylock = true;
  route.old_count = 1924;
  failed |= require(qualify_direct_route(&route) == ROUTE_BULK_UNKNOWN,
                    "count+4 equal to high must be bulk/unknown");
  route.old_count = 1802;
  route.alloc_cpu = 1;
  failed |= require(qualify_direct_route(&route) == ROUTE_DIRECT_MISS,
                    "different CPU must be a direct-PCP miss");
  route.alloc_cpu = 0;
  route.free_type = movable;
  failed |= require(qualify_direct_route(&route) == ROUTE_DIRECT_MISS,
                    "MOVABLE target must miss UNMOVABLE PCP lookup");

  if (failed) return 1;
  puts("PASS: V643 io_uring/PCP model: two order-2 UNMOVABLE allocations; "
       "NORMAL is empty so mm/io both use DMA32; checked affinity proves the "
       "same orchestrator CPU; direct capture still requires UNMOVABLE, "
       "successful PCP trylocks, count+4<high, and <=1 newer exact-list free");
  return 0;
}
