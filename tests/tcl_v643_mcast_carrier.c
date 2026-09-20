#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tcl_v643/mcast_carrier.h"

static int require(int condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

static uint64_t get64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}

int main(void) {
  const uint64_t task = UINT64_C(0xffffff8001234480);
  const uint64_t lock = UINT64_C(0xffffff8001234100);
  struct tcl_v643_mcast_carrier carrier;
  const unsigned base = TCL_V643_MCAST_COMPAT_WAITER_OFF;
  int failed = 0;

  tcl_v643_build_mcast_carrier(&carrier, task, lock, 3, 1);
  failed |= require(sizeof(carrier.bytes) == 0x104,
                    "compat source request size changed");
  failed |= require(get64(carrier.bytes + base + TCL_V643_WAITER_TASK) == task,
                    "task pointer is not at waiter+0x30");
  failed |= require(get64(carrier.bytes + base + TCL_V643_WAITER_LOCK) == lock,
                    "lock pointer is not at waiter+0x38");
  failed |= require(get64(carrier.bytes + base + TCL_V643_WAITER_WAKE_STATE) ==
                        (UINT64_C(3) | (UINT64_C(1) << 32)),
                    "wake/prio pair is not at waiter+0x40");
  failed |= require(base + TCL_V643_WAITER_WW_CTX + sizeof(uint64_t) <=
                        sizeof(carrier.bytes),
                    "complete waiter no longer fits in compat copy");

  for (unsigned i = 0; i < sizeof(carrier.bytes); i++) {
    int expected =
        (i >= base + TCL_V643_WAITER_TASK &&
         i < base + TCL_V643_WAITER_TASK + 8) ||
        (i >= base + TCL_V643_WAITER_LOCK &&
         i < base + TCL_V643_WAITER_LOCK + 8) ||
        (i >= base + TCL_V643_WAITER_WAKE_STATE &&
         i < base + TCL_V643_WAITER_WAKE_STATE + 8);
    if (!expected && carrier.bytes[i] != 0) {
      failed |= require(0, "carrier contains an unintended non-zero byte");
      break;
    }
  }

  if (failed) return 1;
  puts("PASS: byte-exact V643 ARM32 MCAST carrier built at waiter+0x80");
  return 0;
}
