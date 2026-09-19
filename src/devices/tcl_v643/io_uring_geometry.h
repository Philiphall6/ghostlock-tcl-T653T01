#ifndef TCL_V643_IO_URING_GEOMETRY_H
#define TCL_V643_IO_URING_GEOMETRY_H

/* Exact constants recovered from the stock V643 kernel
 * (5.15.180-android14-11), __arm64_sys_io_uring_setup().  These describe
 * the offline allocator model only; the TCL profile remains analysis-only. */
#define TCL_V643_IO_URING_ENTRIES            256U
#define TCL_V643_IO_URING_CQ_ENTRIES         512U
#define TCL_V643_IO_URING_RINGS_BYTES       9536U
#define TCL_V643_IO_URING_SQES_BYTES       16384U
#define TCL_V643_IO_URING_MAP_BYTES        16384U
#define TCL_V643_IO_URING_RINGS_ORDER          2U
#define TCL_V643_IO_URING_SQES_ORDER           2U
#define TCL_V643_IO_URING_GFP             0x00442dc0U

/* Android common 5.15 GFP migratetype bits.  Neither is present in the
 * immediate passed by the V643 io_uring setup path, so its requested PCP
 * migratetype is MIGRATE_UNMOVABLE (0). */
#define TCL_V643_GFP_MOVABLE              0x00000008U
#define TCL_V643_GFP_RECLAIMABLE          0x00000010U
#define TCL_V643_MIGRATE_UNMOVABLE                 0U
#define TCL_V643_MIGRATE_MOVABLE                   1U
#define TCL_V643_MIGRATE_RECLAIMABLE               2U

/* free_unref_page_commit() and get_populated_pcp_list() both select the
 * V643 PCP list with migratetype + order * 4 for orders 0..3. */
#define TCL_V643_PCP_ORDER_MAX                     3U
#define TCL_V643_PCP_LIST_INDEX(order, migratetype) \
  ((unsigned)(migratetype) + ((unsigned)(order) << 2))

#endif
