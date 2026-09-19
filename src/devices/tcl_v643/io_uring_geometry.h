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

/* copy_mm() in the exact V643 binary passes this GFP mask to
 * kmem_cache_alloc(mm_cachep, ...).  Both this mask and the io_uring mask
 * have zone bits 0, which the V643 GFP_ZONE_TABLE maps to ZONE_NORMAL. */
#define TCL_V643_MM_STRUCT_GFP            0x00000cc0U
#define TCL_V643_GFP_ZONE_BITS_MASK       0x0000000fU

/* Exact BTF enum zone_type values plus the archived read-only zoneinfo
 * geometry.  NORMAL has no managed pages on this single-node TV, so both
 * GFP_KERNEL-class requests fall through to DMA32.  ZONE_MOVABLE is above
 * the requested highest index and is not a candidate zone for either call. */
#define TCL_V643_ZONE_DMA32                        0U
#define TCL_V643_ZONE_NORMAL                       1U
#define TCL_V643_ZONE_MOVABLE                      2U
#define TCL_V643_ZONE_NONE                         3U
#define TCL_V643_REQUESTED_HIGHEST_ZONE \
  TCL_V643_ZONE_NORMAL
#define TCL_V643_DMA32_MANAGED_PAGES          277520U
#define TCL_V643_NORMAL_MANAGED_PAGES              0U
#define TCL_V643_MOVABLE_MANAGED_PAGES         335298U

/* Android common 5.15 GFP migratetype bits.  Neither is present in the
 * immediate passed by the V643 io_uring setup path, so its requested PCP
 * migratetype is MIGRATE_UNMOVABLE (0). */
#define TCL_V643_GFP_MOVABLE              0x00000008U
#define TCL_V643_GFP_RECLAIMABLE          0x00000010U
#define TCL_V643_MIGRATE_UNMOVABLE                 0U
#define TCL_V643_MIGRATE_MOVABLE                   1U
#define TCL_V643_MIGRATE_RECLAIMABLE               2U

/* The exact V643 move_freepages_block() masks the PFN with ~0x3ff and
 * steal_suitable_fallback() compares the compatible/free population against
 * 0x1ff.  Consequently a pageblock is 2^10 base pages and the retag threshold
 * is 512 pages.  These constants only feed the offline allocator model. */
#define TCL_V643_PAGEBLOCK_ORDER                   10U
#define TCL_V643_PAGEBLOCK_PAGES \
  (1U << TCL_V643_PAGEBLOCK_ORDER)
#define TCL_V643_PAGEBLOCK_RETAG_THRESHOLD \
  (1U << (TCL_V643_PAGEBLOCK_ORDER - 1U))

/* free_unref_page_commit() and get_populated_pcp_list() both select the
 * V643 PCP list with migratetype + order * 4 for orders 0..3. */
#define TCL_V643_PCP_ORDER_MAX                     3U
#define TCL_V643_PCP_LIST_INDEX(order, migratetype) \
  ((unsigned)(migratetype) + ((unsigned)(order) << 2))

#endif
