#include <stdint.h>
#include <stdio.h>

#include "tcl_v643/stack_geometry.h"

_Static_assert(TCL_V643_EL0_SVC_FRAME_SIZE +
                   TCL_V643_DO_EL0_SVC_FRAME_SIZE +
                   TCL_V643_EL0_SVC_COMMON_FRAME_SIZE +
                   TCL_V643_INVOKE_SYSCALL_FRAME_SIZE ==
               TCL_V643_SYSCALL_FROM_EL0_SP,
               "V643 syscall entry depth changed");
_Static_assert(TCL_V643_RANDOM_KSTACK_MAX %
                   TCL_V643_RANDOM_KSTACK_ALIGN == 0,
               "random-kstack range is not aligned");

static int require(int condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

/* Coordinates are signed offsets below the fixed kernel-stack top at entry
 * to el0_svc.  This is an arithmetic model only; it never enters the kernel. */
static int waiter_coordinate(unsigned random_offset) {
  return -(int)(TCL_V643_SYSCALL_FROM_EL0_SP + random_offset +
                TCL_V643_WAITER_FROM_SYSCALL_SP);
}

static int stack_fds_coordinate(unsigned random_offset) {
  return -(int)(TCL_V643_SYSCALL_FROM_EL0_SP + random_offset +
                TCL_V643_STACK_FDS_FROM_SYSCALL_SP);
}

int main(void) {
  int failed = 0;
  unsigned alias_pairs = 0;
  const unsigned values = TCL_V643_RANDOM_KSTACK_MAX /
                              TCL_V643_RANDOM_KSTACK_ALIGN +
                          1;

  failed |= require(TCL_V643_RANDOM_KSTACK_DEFAULT_ENABLED == 0,
                    "exact stock V643 default must remain disabled");
  failed |= require(waiter_coordinate(0) == -0x260,
                    "stale waiter coordinate changed");
  failed |= require(stack_fds_coordinate(0) == -0x290,
                    "pselect stack_fds coordinate changed");
  failed |= require(waiter_coordinate(0) - stack_fds_coordinate(0) ==
                        (int)TCL_V643_STACK_FDS_TO_WAITER,
                    "disabled-randomization alias is not +0x30");
  failed |= require(-(int)TCL_V643_HANDLE_SIGNAL_FROM_EL0_SP >
                        waiter_coordinate(0),
                    "signal-frame landmark should be above stale waiter");

  for (unsigned futex = 0; futex <= TCL_V643_RANDOM_KSTACK_MAX;
       futex += TCL_V643_RANDOM_KSTACK_ALIGN) {
    for (unsigned pselect = 0; pselect <= TCL_V643_RANDOM_KSTACK_MAX;
         pselect += TCL_V643_RANDOM_KSTACK_ALIGN) {
      int delta = waiter_coordinate(futex) -
                  stack_fds_coordinate(pselect);
      if (delta == (int)TCL_V643_STACK_FDS_TO_WAITER) {
        alias_pairs++;
        failed |= require(futex == pselect,
                          "fixed alias matched unequal random offsets");
      }
    }
  }
  failed |= require(alias_pairs == values,
                    "randomized alias-pair count changed");

  if (failed) return 1;
  printf("el0_sp: syscall=-0x%x waiter=-0x%x stack_fds=-0x%x delta=+0x%x\n",
         TCL_V643_SYSCALL_FROM_EL0_SP,
         -waiter_coordinate(0), -stack_fds_coordinate(0),
         TCL_V643_STACK_FDS_TO_WAITER);
  printf("random-kstack: default=off dormant_range=0..0x%x step=0x%x "
         "fixed_alias_pairs=%u/%u\n",
         TCL_V643_RANDOM_KSTACK_MAX, TCL_V643_RANDOM_KSTACK_ALIGN,
         alias_pairs, values * values);
  puts("PASS: exact stock V643 keeps the futex/pselect +0x30 coordinate deterministic");
  return 0;
}
