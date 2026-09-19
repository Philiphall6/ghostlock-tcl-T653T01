#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "offsets.h"

enum requeue_pi_state {
  Q_REQUEUE_PI_NONE = 0,
  Q_REQUEUE_PI_IGNORE = 1,
  Q_REQUEUE_PI_IN_PROGRESS = 2,
  Q_REQUEUE_PI_WAIT = 3,
};

struct model_task {
  uintptr_t pi_blocked_on;
};

struct model_waiter {
  struct model_task *task;
  uintptr_t lock;
};

struct model_lock {
  struct model_task *owner;
};

static int require(bool condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

/* The exact V643 task_blocks_on_rt_mutex() stores the waiter at task+0x910
 * before the later PI-chain walk can return -EDEADLK. */
static int model_task_blocks_then_chain_deadlock(struct model_task *proxy,
                                                 struct model_waiter *waiter) {
  proxy->pi_blocked_on = (uintptr_t)waiter;
  return -EDEADLK;
}

/* Models only the ownership graph established by main.c before the requeue:
 * proxy owns chain; owner owns target and is blocked on chain.  Requeueing
 * proxy onto target must therefore detect proxy -> owner -> proxy, and the
 * target owner differs from proxy so this is not the pre-enqueue fast path. */
static bool model_post_enqueue_cycle(const struct model_task *proxy,
                                     const struct model_task *owner,
                                     const struct model_lock *target,
                                     const struct model_lock *chain,
                                     const struct model_waiter *owner_waiter) {
  if (target->owner == proxy) return false;
  if (target->owner != owner) return false;
  if (owner_waiter->task != owner) return false;
  if (owner->pi_blocked_on != (uintptr_t)owner_waiter) return false;
  if (owner_waiter->lock != (uintptr_t)chain) return false;
  return chain->owner == proxy;
}

/* Vulnerable V643 behavior: remove_waiter() obtains current via sp_el0 and
 * clears current+0x910, even though waiter->task is the proxy task. */
static void model_remove_waiter_v643(struct model_task *current,
                                     struct model_waiter *waiter) {
  (void)waiter;
  current->pi_blocked_on = 0;
}

/* Upstream fixed behavior, retained only as a comparison oracle. */
static void model_remove_waiter_fixed(struct model_task *current,
                                      struct model_waiter *waiter) {
  (void)current;
  waiter->task->pi_blocked_on = 0;
}

/* Exact negative-result transition used by futex_requeue_pi_complete(). */
static enum requeue_pi_state model_complete_negative(
    enum requeue_pi_state old_state) {
  if (old_state == Q_REQUEUE_PI_IN_PROGRESS)
    return Q_REQUEUE_PI_NONE;
  if (old_state == Q_REQUEUE_PI_WAIT)
    return Q_REQUEUE_PI_IGNORE;
  return old_state;
}

static const struct kernel_offsets *find_v643(void) {
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(known_offsets[i].uname_r, "5.15.180-android14-11") == 0)
      return &known_offsets[i];
  }
  return NULL;
}

int main(void) {
  int failed = 0;
  const struct kernel_offsets *tcl = find_v643();
  struct model_task requeuer = {0};
  struct model_task proxy = {0};
  struct model_task owner = {0};
  struct model_lock chain = {.owner = &proxy};
  struct model_lock target = {.owner = &owner};
  struct model_waiter owner_waiter = {
      .task = &owner,
      .lock = (uintptr_t)&chain,
  };
  struct model_waiter stack_waiter = {
      .task = &proxy,
      .lock = (uintptr_t)&target,
  };
  enum requeue_pi_state state = Q_REQUEUE_PI_IN_PROGRESS;

  failed |= require(tcl != NULL, "TCL V643 profile is missing");
  if (!tcl) return 1;
  failed |= require(tcl->task_pi_blocked_on == 0x910,
                    "V643 task.pi_blocked_on offset changed");
  failed |= require(tcl->waiter_task == 0x30 &&
                        tcl->waiter_lock == 0x38,
                    "V643 waiter task/lock offsets changed");

  owner.pi_blocked_on = (uintptr_t)&owner_waiter;
  failed |= require(target.owner != &proxy,
                    "model accidentally selects pre-enqueue self-deadlock");
  failed |= require(model_post_enqueue_cycle(
                        &proxy, &owner, &target, &chain, &owner_waiter),
                    "proxy/owner ownership graph does not close after enqueue");

  int ret = model_task_blocks_then_chain_deadlock(&proxy, &stack_waiter);
  failed |= require(ret == -EDEADLK,
                    "model must take the post-enqueue chain-deadlock branch");
  failed |= require(proxy.pi_blocked_on == (uintptr_t)&stack_waiter,
                    "proxy task was not armed before the modeled deadlock");

  model_remove_waiter_v643(&requeuer, &stack_waiter);
  state = model_complete_negative(state);
  failed |= require(requeuer.pi_blocked_on == 0,
                    "vulnerable rollback should clear current/requeuer");
  failed |= require(proxy.pi_blocked_on == (uintptr_t)&stack_waiter,
                    "vulnerable rollback unexpectedly cleared proxy task");
  failed |= require(state == Q_REQUEUE_PI_NONE,
                    "negative IN_PROGRESS completion must become NONE");

  model_remove_waiter_fixed(&requeuer, &stack_waiter);
  failed |= require(proxy.pi_blocked_on == 0,
                    "fixed rollback must clear waiter->task");

  if (failed) return 1;
  puts("V643 exact offsets: task.pi_blocked_on=0x910 waiter.task=0x30 waiter.lock=0x38");
  puts("cycle topology: proxy owns chain; target owner blocks on chain; requeue closes cycle post-enqueue");
  puts("vulnerable rollback: current cleared, proxy pointer retained, state 2 -> 0");
  puts("fixed rollback: waiter->task pointer cleared");
  puts("PASS: host-only V643 pi_blocked_on rollback model");
  return 0;
}
