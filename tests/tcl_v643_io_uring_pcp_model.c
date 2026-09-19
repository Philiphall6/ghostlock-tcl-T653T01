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

struct pcp_list {
  enum page_id pages[MODEL_DEPTH];
  unsigned count;
};

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
  failed |= require((TCL_V643_IO_URING_GFP &
                    (TCL_V643_GFP_MOVABLE |
                     TCL_V643_GFP_RECLAIMABLE)) == 0,
                    "io_uring GFP unexpectedly requests a movable type");
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

  /* At equality the V643 branch enters free_pcppages_bulk().  The direct
   * LIFO proof must stop here because the target can leave the PCP list. */
  struct pcp_cpu at_high = {.count = 1924, .high = 1928};
  failed |= require(!pcp_free(&at_high, order, unmovable, PAGE_TARGET) &&
                    at_high.bulk_path,
                    "count + four equal to high must enter bulk path");

  if (failed) return 1;
  puts("PASS: V643 io_uring/PCP model: two order-2 UNMOVABLE allocations; "
       "empty-list refill=15 at batch=63; direct capture is conditional "
       "on same CPU/type, count+4<high, and at most one newer exact-list free");
  return 0;
}
