#include <stdbool.h>
#include <stdio.h>

struct route_result {
  int rounds;
  int hits;
  int nice;
  bool complete;
};

static int require(bool condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

/* Models the control decisions only. A true entry means that round's
 * synchronous PI consumer reported one verified erase. */
static struct route_result model_rounds(int plans, const bool *landed) {
  struct route_result r = {0};
  for (int round = 1; round <= plans; round++) {
    if (round > 1 &&
        (r.hits <= 0 || r.hits >= plans || r.nice >= 19))
      break;
    r.rounds++;
    r.nice += 7;
    if (r.nice > 19) r.nice = 19;
    if (landed[round - 1]) r.hits++;
    if (r.hits >= plans) {
      r.complete = true;
      break;
    }
  }
  return r;
}

int main(void) {
  int failed = 0;
  const bool all_three[] = {true, true, true};
  const bool first_miss[] = {false, true, true};
  const bool two_writes[] = {true, true};

  struct route_result full = model_rounds(3, all_three);
  failed |= require(full.complete && full.rounds == 3 &&
                        full.hits == 3 && full.nice == 19,
                    "three-write route must use fresh 7/14/19 rounds");

  struct route_result miss = model_rounds(3, first_miss);
  failed |= require(!miss.complete && miss.rounds == 1 && miss.hits == 0,
                    "zero-hit first round must not claim same-page retry");

  struct route_result two = model_rounds(2, two_writes);
  failed |= require(two.complete && two.rounds == 2 &&
                        two.hits == 2 && two.nice == 14,
                    "two-write route must complete in two fresh frames");

  if (failed) return 1;
  puts("three writes: rounds=3 nice=7/14/19 complete");
  puts("first-round miss: no unproved same-page retry");
  puts("PASS: host-only TCL pselect multi-round control model");
  return 0;
}
