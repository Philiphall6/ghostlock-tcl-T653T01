#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Host-only state model for the V643 GhostLock cleanup sequence.
 *
 * This deliberately contains no futex syscall, kernel address, timing
 * choreography or exploit implementation.  It records the invariants seen in
 * the exact V643 disassembly:
 *
 *   task_blocks_on_rt_mutex(): task->pi_blocked_on = waiter
 *   remove_waiter():           dequeue lock tree, dequeue owner PI tree,
 *                              current->pi_blocked_on = NULL
 *
 * The vulnerable proxy rollback leaves only the proxy task pointer stale; the
 * old waiter has already been removed from both rb trees.  A timed-out dummy
 * PI lock can replace and then clear that pointer, but only after all chain
 * walkers are quiescent and only when it is issued by a non-leader thread
 * against a futex word owned by the live process leader.
 */

struct model_task {
  uint32_t tid;
  uintptr_t pi_blocked_on;
  unsigned int pi_waiters;
};

struct model_lock {
  struct model_task *owner;
  unsigned int waiters;
};

struct model_waiter {
  struct model_task *task;
  struct model_lock *lock;
  bool lock_tree_linked;
  bool owner_pi_tree_linked;
};

static int require(bool condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

static void model_enqueue(struct model_task *task, struct model_lock *lock,
                          struct model_waiter *waiter) {
  waiter->task = task;
  waiter->lock = lock;
  waiter->lock_tree_linked = true;
  waiter->owner_pi_tree_linked = lock->owner != NULL;
  lock->waiters++;
  if (lock->owner) lock->owner->pi_waiters++;

  /* Exact V643 behavior: no rejection of a pre-existing dangling value. */
  task->pi_blocked_on = (uintptr_t)waiter;
}

static void model_remove_waiter_v643(struct model_task *current,
                                     struct model_waiter *waiter) {
  if (waiter->lock_tree_linked) {
    waiter->lock_tree_linked = false;
    waiter->lock->waiters--;
  }
  if (waiter->owner_pi_tree_linked) {
    waiter->owner_pi_tree_linked = false;
    waiter->lock->owner->pi_waiters--;
  }

  /* CVE behavior in the exact image: current, not waiter->task. */
  current->pi_blocked_on = 0;
}

static int model_disarm(struct model_task *worker,
                        struct model_task *process_leader,
                        unsigned int active_walkers) {
  struct model_lock dummy_lock = {.owner = process_leader};
  struct model_waiter dummy_waiter = {0};

  if (active_walkers != 0) return -EBUSY;
  if (worker == process_leader || worker->tid == process_leader->tid)
    return -EDEADLK; /* owner == task: early exit, no waiter publication */

  model_enqueue(worker, &dummy_lock, &dummy_waiter);
  model_remove_waiter_v643(worker, &dummy_waiter); /* expired timeout */

  if (worker->pi_blocked_on != 0 || dummy_lock.waiters != 0 ||
      process_leader->pi_waiters != 0 || dummy_waiter.lock_tree_linked ||
      dummy_waiter.owner_pi_tree_linked)
    return -EUCLEAN;
  return -ETIMEDOUT;
}

int main(void) {
  int failed = 0;
  struct model_task requeuer = {.tid = 1000};
  struct model_task proxy = {.tid = 1001};
  struct model_task original_owner = {.tid = 1002};
  struct model_lock original_lock = {.owner = &original_owner};
  struct model_waiter stale_waiter = {0};

  model_enqueue(&proxy, &original_lock, &stale_waiter);
  model_remove_waiter_v643(&requeuer, &stale_waiter);

  failed |= require(proxy.pi_blocked_on == (uintptr_t)&stale_waiter,
                    "proxy must retain the dangling waiter after rollback");
  failed |= require(original_lock.waiters == 0,
                    "old waiter must already be absent from lock rb tree");
  failed |= require(original_owner.pi_waiters == 0,
                    "old waiter must already be absent from owner PI tree");
  failed |= require(!stale_waiter.lock_tree_linked &&
                        !stale_waiter.owner_pi_tree_linked,
                    "old waiter retains a modeled rb-tree link");

  failed |= require(model_disarm(&proxy, &requeuer, 1) == -EBUSY,
                    "disarm must refuse while a PI chain walk is active");
  failed |= require(proxy.pi_blocked_on == (uintptr_t)&stale_waiter,
                    "refused disarm must not alter the dangling pointer");
  failed |= require(model_disarm(&requeuer, &requeuer, 0) == -EDEADLK,
                    "leader-as-worker must hit owner==task early deadlock");

  failed |= require(model_disarm(&proxy, &requeuer, 0) == -ETIMEDOUT,
                    "quiescent non-leader disarm must end in ETIMEDOUT");
  failed |= require(proxy.pi_blocked_on == 0,
                    "dummy timeout did not clear proxy pi_blocked_on");
  failed |= require(original_lock.waiters == 0 &&
                        original_owner.pi_waiters == 0,
                    "disarm disturbed the already-detached original trees");

  /* Repeat the overwrite/dequeue/clear transition to catch state leakage in
   * the model. This is not a live-kernel stability claim. */
  for (unsigned int i = 0; i < 100000 && !failed; ++i) {
    proxy.pi_blocked_on = (uintptr_t)&stale_waiter;
    int ret = model_disarm(&proxy, &requeuer, 0);
    if (ret != -ETIMEDOUT || proxy.pi_blocked_on != 0 ||
        requeuer.pi_waiters != 0) {
      failed |= require(false, "repeated cleanup invariant failed");
      break;
    }
  }

  if (failed) return 1;
  puts("rollback: old waiter detached from lock and owner PI rb trees");
  puts("disarm preconditions: zero active walkers; worker TID != leader TID");
  puts("dummy timeout: stale pointer overwritten, new waiter dequeued, pointer cleared");
  puts("PASS: 100000 host-only V643 cleanup state transitions");
  return 0;
}
