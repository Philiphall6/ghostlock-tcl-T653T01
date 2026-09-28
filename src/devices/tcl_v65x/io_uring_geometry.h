#ifndef TCL_V65X_IO_URING_GEOMETRY_H
#define TCL_V65X_IO_URING_GEOMETRY_H

/* Exact static allocator constants recovered independently from the stock
 * T653T01 V655, V665 and V667 kernels (5.15.192-android14-11).  These values
 * describe code and data layouts only.  They do not claim that the live PCP
 * state, CPU affinity, zone selection or concurrent drain conditions have
 * been validated on a television running V65x. */
#define TCL_V65X_IO_URING_ENTRIES             256U
#define TCL_V65X_IO_URING_CQ_ENTRIES          512U
#define TCL_V65X_IO_URING_RINGS_BYTES        9536U
#define TCL_V65X_IO_URING_SQES_BYTES        16384U
#define TCL_V65X_IO_URING_MAP_BYTES         16384U
#define TCL_V65X_IO_URING_RINGS_ORDER           2U
#define TCL_V65X_IO_URING_SQES_ORDER            2U
#define TCL_V65X_IO_URING_GFP              0x00442dc0U
#define TCL_V65X_MM_STRUCT_GFP             0x00000cc0U
#define TCL_V65X_GFP_ZONE_BITS_MASK        0x0000000fU
#define TCL_V65X_GFP_MOVABLE               0x00000008U
#define TCL_V65X_GFP_RECLAIMABLE           0x00000010U

#define TCL_V65X_ZONE_NORMAL                         1U
#define TCL_V65X_REQUESTED_HIGHEST_ZONE \
  TCL_V65X_ZONE_NORMAL
#define TCL_V65X_MIGRATE_UNMOVABLE                   0U
#define TCL_V65X_MIGRATE_MOVABLE                     1U
#define TCL_V65X_MIGRATE_RECLAIMABLE                 2U

/* CONFIG_HUGETLBFS is disabled and CONFIG_FORCE_MAX_ZONEORDER is 11.  The
 * exact machine code confirms pageblock_order = MAX_ORDER - 1 = 10: it masks
 * PFNs with ~0x3ff and compares the steal population against 0x1ff.  The
 * vendor CONFIG_PAGE_BLOCK_ORDER=11 line is not the compiled pageblock order
 * in these images. */
#define TCL_V65X_PAGEBLOCK_ORDER                     10U
#define TCL_V65X_PAGEBLOCK_PAGES \
  (1U << TCL_V65X_PAGEBLOCK_ORDER)
#define TCL_V65X_PAGEBLOCK_RETAG_THRESHOLD \
  (1U << (TCL_V65X_PAGEBLOCK_ORDER - 1U))

#define TCL_V65X_PCP_ORDER_MAX                        3U
#define TCL_V65X_PCP_LIST_INDEX(order, migratetype) \
  ((unsigned)(migratetype) + ((unsigned)(order) << 2))

/* This must remain zero until a V65x runtime or an exact instrumented kernel
 * proves zone topology, PCP high/batch/count, same-CPU handoff, trylocks and
 * absence/handling of concurrent drain paths. */
#define TCL_V65X_LIVE_PCP_CHOREOGRAPHY_VALIDATED      0U

#endif
