#include <stdio.h>

#include "tcl_v643/mcast_geometry.h"
#include "tcl_v643/stack_geometry.h"

_Static_assert(TCL_V643_MCAST_WRAPPER_FRAME +
                   TCL_V643_MCAST_SYS_FRAME +
                   TCL_V643_MCAST_SOCK_COMMON_FRAME +
                   TCL_V643_MCAST_UDP_FRAME +
                   TCL_V643_MCAST_IP_FRAME ==
               TCL_V643_MCAST_FRAME_TOTAL,
               "V643 MCAST call-chain frame total changed");

static int require(int condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

int main(void) {
  int failed = 0;
  unsigned native_start = TCL_V643_MCAST_FRAME_TOTAL -
                          TCL_V643_MCAST_NATIVE_LOCAL_OFF;
  unsigned compat_start = TCL_V643_MCAST_FRAME_TOTAL -
                          TCL_V643_MCAST_COMPAT_LOCAL_OFF;
  unsigned native_waiter = native_start - TCL_V643_WAITER_FROM_SYSCALL_SP;
  unsigned compat_waiter = compat_start - TCL_V643_WAITER_FROM_SYSCALL_SP;

  failed |= require(native_start == TCL_V643_MCAST_NATIVE_FROM_SYSCALL_SP,
                    "native group_source_req coordinate changed");
  failed |= require(compat_start == TCL_V643_MCAST_COMPAT_FROM_SYSCALL_SP,
                    "compat group_source_req coordinate changed");
  failed |= require(native_waiter == TCL_V643_MCAST_NATIVE_WAITER_OFF,
                    "native waiter displacement changed");
  failed |= require(compat_waiter == TCL_V643_MCAST_COMPAT_WAITER_OFF,
                    "compat waiter displacement changed");

  failed |= require(native_waiter >= TCL_V643_MCAST_NATIVE_COPY_SIZE,
                    "native MCAST unexpectedly reaches the stale waiter");
  failed |= require(compat_waiter + TCL_V643_WAITER_SIZE <=
                        TCL_V643_MCAST_COMPAT_COPY_SIZE,
                    "compat MCAST no longer contains the full waiter");
  failed |= require(TCL_V643_COMPAT_SETSOCKOPT_TABLE_ENTRY ==
                        0xffffffc009459dc8ULL,
                    "compat syscall 294 no longer selects setsockopt");

  if (failed) return 1;

  printf("native: copy=SP-0x%x size=0x%x waiter_off=0x%x => MISS by 0x%x\n",
         native_start, TCL_V643_MCAST_NATIVE_COPY_SIZE, native_waiter,
         native_waiter - TCL_V643_MCAST_NATIVE_COPY_SIZE);
  printf("compat: copy=SP-0x%x size=0x%x waiter_off=0x%x end=0x%x => FIT\n",
         compat_start, TCL_V643_MCAST_COMPAT_COPY_SIZE, compat_waiter,
         compat_waiter + TCL_V643_WAITER_SIZE);
  puts("PASS: exact V643 MCAST carrier is viable only through AArch32 compat");
  return 0;
}
