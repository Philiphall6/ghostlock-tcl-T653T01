#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct observation {
  uint32_t sid;
  int probe_ok;
  const char *context;
};

static uint32_t select_candidate(const uint32_t *candidates, int count,
                                 const struct observation *obs, int nobs,
                                 const char *expected_context) {
  for (int i = 0; i < count; i++) {
    int duplicate = 0;
    for (int j = 0; j < i; j++)
      if (candidates[j] == candidates[i]) duplicate = 1;
    if (duplicate) continue;
    for (int j = 0; j < nobs; j++) {
      if (obs[j].sid != candidates[i] || !obs[j].probe_ok ||
          !obs[j].context)
        continue;
      if (strcmp(obs[j].context, expected_context) == 0)
        return candidates[i];
    }
  }
  return 0;
}

static int expect(const char *name, uint32_t got, uint32_t want) {
  if (got == want) return 0;
  fprintf(stderr, "%s: got %u want %u\n", name, got, want);
  return 1;
}

int main(void) {
  static const char shell[] = "u:r:shell:s0";
  int failed = 0;

  {
    const uint32_t c[] = {1374};
    const struct observation o[] = {{1374, 1, shell}};
    failed |= expect("kernel-read-denied/default-recovers",
                     select_candidate(c, 1, o, 1, shell), 1374);
  }
  {
    const uint32_t c[] = {1374};
    const struct observation o[] = {{1374, 1, "u:r:adbd:s0"}};
    failed |= expect("access-only-is-not-enough",
                     select_candidate(c, 1, o, 1, shell), 0);
  }
  {
    const uint32_t c[] = {900, 900, 1374};
    const struct observation o[] = {
      {900, 0, NULL}, {1374, 1, shell}
    };
    failed |= expect("deduplicate-then-default",
                     select_candidate(c, 3, o, 2, shell), 1374);
  }
  {
    const uint32_t c[] = {1374};
    const struct observation o[] = {{1374, 0, NULL}};
    failed |= expect("fail-closed",
                     select_candidate(c, 1, o, 1, shell), 0);
  }

  if (failed) return 1;
  puts("TCL V643 SID PROBE MODEL PASS");
  return 0;
}
