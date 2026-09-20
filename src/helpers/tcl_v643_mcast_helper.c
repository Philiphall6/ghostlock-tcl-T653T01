#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tcl_v643/mcast_carrier.h"
#include "tcl_v643/mcast_helper_protocol.h"

static uint64_t get64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}

static int selftest(void) {
  const uint64_t task = UINT64_C(0xffffff8001234480);
  const uint64_t lock = UINT64_C(0xffffff8001234100);
  const unsigned base = TCL_V643_MCAST_COMPAT_WAITER_OFF;
  struct tcl_v643_mcast_carrier carrier;
  struct tcl_v643_mcast_helper_message message = {
      .magic = TCL_V643_MCAST_HELPER_MAGIC,
      .version = TCL_V643_MCAST_HELPER_VERSION,
      .size = sizeof(message),
      .fake_task = task,
      .fake_lock = lock,
      .wake_state = 3,
      .prio = 1,
  };

  if (sizeof(void *) != 4) {
    fprintf(stderr, "FAIL: helper is not an AArch32/ILP32 executable\n");
    return 1;
  }
  tcl_v643_build_mcast_carrier(&carrier, message.fake_task,
                               message.fake_lock, message.wake_state,
                               message.prio);
  if (message.magic != TCL_V643_MCAST_HELPER_MAGIC ||
      message.version != 1 || message.size != 40 ||
      sizeof(carrier.bytes) != TCL_V643_MCAST_COMPAT_COPY_SIZE ||
      get64(carrier.bytes + base + TCL_V643_WAITER_TASK) != task ||
      get64(carrier.bytes + base + TCL_V643_WAITER_LOCK) != lock) {
    fprintf(stderr, "FAIL: helper protocol/carrier invariant\n");
    return 1;
  }

  puts("PASS: AArch32 TCL V643 MCAST helper ABI and +0x80 carrier layout");
  puts("SAFE: self-test only; no futex, setsockopt, reclaim or kernel address used");
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
    return selftest();

  fprintf(stderr,
          "REFUSED: the TCL MCAST helper has no arming command; use --selftest\n");
  return 2;
}
