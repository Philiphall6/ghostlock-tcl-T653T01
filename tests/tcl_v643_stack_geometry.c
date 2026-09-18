#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tcl_v643/stack_geometry.h"
#include "tcl_v643/pselect_carrier.h"

_Static_assert(TCL_V643_PSELECT_FRAME_SIZE +
                   TCL_V643_CORE_SELECT_FRAME_SIZE -
                   TCL_V643_CORE_SELECT_STACK_FDS_OFF ==
               TCL_V643_STACK_FDS_FROM_SYSCALL_SP,
               "pselect stack_fds delta changed");
_Static_assert(TCL_V643_STACK_FDS_FROM_SYSCALL_SP -
                   TCL_V643_WAITER_FROM_SYSCALL_SP ==
               TCL_V643_STACK_FDS_TO_WAITER,
               "waiter-to-stack_fds delta changed");
_Static_assert(TCL_V643_FDSET_BYTES * TCL_V643_FDSET_COUNT ==
               TCL_V643_STACK_FDS_BYTES,
               "six fd_set blocks no longer fit expected stack_fds size");
_Static_assert(TCL_V643_FDSET_SLOT(TCL_V643_WAITER_TASK) ==
                   TCL_V643_IN_EXCEPT,
               "waiter.task must land in input exceptfds");
_Static_assert(TCL_V643_FDSET_SLOT(TCL_V643_WAITER_LOCK) ==
                   TCL_V643_IN_EXCEPT,
               "waiter.lock must land in input exceptfds");
_Static_assert(TCL_V643_FDSET_SLOT(TCL_V643_WAITER_WAKE_STATE) ==
                   TCL_V643_IN_EXCEPT,
               "waiter wake/prio must land in input exceptfds");
_Static_assert(TCL_V643_FDSET_SLOT(TCL_V643_WAITER_DEADLINE) ==
                   TCL_V643_OUT_READ,
               "waiter.deadline must land in zeroed output readfds");

struct field_map {
  const char *name;
  unsigned waiter_off;
  unsigned size;
};

static const char *slot_name(unsigned slot) {
  static const char *const names[] = {
      "in.read", "in.write", "in.except",
      "out.read", "out.write", "out.except",
  };
  return slot < TCL_V643_FDSET_COUNT ? names[slot] : "outside";
}

static int require(int condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

int main(void) {
  static const struct field_map fields[] = {
      {"tree", TCL_V643_WAITER_TREE, 0x18},
      {"pi_tree", TCL_V643_WAITER_PI_TREE, 0x18},
      {"task", TCL_V643_WAITER_TASK, 8},
      {"lock", TCL_V643_WAITER_LOCK, 8},
      {"wake_state", TCL_V643_WAITER_WAKE_STATE, 4},
      {"prio", TCL_V643_WAITER_PRIO, 4},
      {"deadline", TCL_V643_WAITER_DEADLINE, 8},
      {"ww_ctx", TCL_V643_WAITER_WW_CTX, 8},
  };
  uint8_t stack_fds[TCL_V643_STACK_FDS_BYTES] = {0};
  uint8_t *waiter = stack_fds + TCL_V643_STACK_FDS_TO_WAITER;
  const uint64_t fake_task = UINT64_C(0xffffff8001234000);
  const uint64_t fake_lock = UINT64_C(0xffffff8001234800);
  const uint32_t wake_state = 3;
  const int32_t prio = 1;
  uint64_t got64;
  uint32_t got32;
  struct tcl_v643_pselect_carrier carrier;
  int failed = 0;

  memcpy(waiter + TCL_V643_WAITER_TASK, &fake_task, sizeof(fake_task));
  memcpy(waiter + TCL_V643_WAITER_LOCK, &fake_lock, sizeof(fake_lock));
  memcpy(waiter + TCL_V643_WAITER_WAKE_STATE,
         &wake_state, sizeof(wake_state));
  memcpy(waiter + TCL_V643_WAITER_PRIO, &prio, sizeof(prio));

  memcpy(&got64, waiter + TCL_V643_WAITER_TASK, sizeof(got64));
  failed |= require(got64 == fake_task, "task pointer mapping failed");
  memcpy(&got64, waiter + TCL_V643_WAITER_LOCK, sizeof(got64));
  failed |= require(got64 == fake_lock, "lock pointer mapping failed");
  memcpy(&got32, waiter + TCL_V643_WAITER_WAKE_STATE, sizeof(got32));
  failed |= require(got32 == wake_state, "wake_state mapping failed");
  memcpy(&got32, waiter + TCL_V643_WAITER_PRIO, sizeof(got32));
  failed |= require(got32 == (uint32_t)prio, "prio mapping failed");
  memcpy(&got64, waiter + TCL_V643_WAITER_DEADLINE, sizeof(got64));
  failed |= require(got64 == 0, "zeroed output set must supply deadline=0");
  memcpy(&got64, waiter + TCL_V643_WAITER_WW_CTX, sizeof(got64));
  failed |= require(got64 == 0, "zeroed output set must supply ww_ctx=NULL");

  tcl_v643_build_pselect_carrier(
      &carrier, fake_task, fake_lock, wake_state, prio);
  failed |= require(memcmp(stack_fds, &carrier, sizeof(carrier)) == 0,
                    "pselect carrier does not reproduce the exact input sets");
  for (unsigned fd = 0; fd < 128; fd++)
    failed |= require(!tcl_v643_carrier_fd_selected(&carrier, fd),
                      "carrier unexpectedly aliases a low control fd");

  printf("syscall_sp: stack_fds=-0x%x waiter=-0x%x delta=+0x%x\n",
         TCL_V643_STACK_FDS_FROM_SYSCALL_SP,
         TCL_V643_WAITER_FROM_SYSCALL_SP,
         TCL_V643_STACK_FDS_TO_WAITER);
  for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    unsigned slot = TCL_V643_FDSET_SLOT(fields[i].waiter_off);
    unsigned off = TCL_V643_FDSET_SLOT_OFF(fields[i].waiter_off);
    printf("%-10s waiter+0x%02x -> %-10s +0x%02x size=0x%x\n",
           fields[i].name, fields[i].waiter_off,
           slot_name(slot), off, fields[i].size);
  }

  if (failed) return 1;
  puts("PASS: exact V643 pselect stack geometry can cover critical waiter fields");
  return 0;
}
