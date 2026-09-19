#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "offsets.h"

#define MAX_PARTIAL_PAGES 64

struct partial_page {
  bool controlled;
  bool target;
  bool empty;
  unsigned free_objects_at_insert;
};

struct slub_model {
  struct partial_page cpu[MAX_PARTIAL_PAGES];
  unsigned cpu_pages;
  unsigned cpu_pobjects;
  unsigned node_partial;
  unsigned controlled_to_node;
  unsigned drains;
  bool target_discarded;
};

static int require(bool condition, const char *message) {
  if (condition) return 0;
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

/* Exact V643 put_cpu_partial rule: the existing list is drained only when
 * drain=true and old_head->pobjects is strictly greater than cpu_partial.
 * The new page is inserted after that test. */
static bool put_partial(struct slub_model *m, unsigned cpu_partial,
                        struct partial_page page) {
  bool drained = false;
  if (m->cpu_pages && m->cpu_pobjects > cpu_partial) {
    drained = true;
    m->drains++;
    for (unsigned i = 0; i < m->cpu_pages; i++) {
      const struct partial_page *p = &m->cpu[i];
      if (p->empty && m->node_partial >= 5) {
        if (p->target) m->target_discarded = true;
        continue;
      }
      m->node_partial++;
      if (p->controlled) m->controlled_to_node++;
    }
    m->cpu_pages = 0;
    m->cpu_pobjects = 0;
  }

  if (m->cpu_pages >= MAX_PARTIAL_PAGES) return drained;
  memmove(&m->cpu[1], &m->cpu[0],
          m->cpu_pages * sizeof(m->cpu[0]));
  m->cpu[0] = page;
  m->cpu_pages++;
  m->cpu_pobjects += page.free_objects_at_insert;
  return drained;
}

static struct partial_page one_free(bool controlled) {
  return (struct partial_page) {
    .controlled = controlled,
    .free_objects_at_insert = 1,
  };
}

int main(void) {
  const struct kernel_offsets *tcl = NULL;
  int failed = 0;

  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(known_offsets[i].uname_r,
               "5.15.180-android14-11") == 0) {
      tcl = &known_offsets[i];
      break;
    }
  }
  failed |= require(tcl != NULL, "V643 profile missing");
  if (!tcl) return 1;
  failed |= require(tcl->slub_cpu_partial == 6,
                    "V643 cpu_partial must be 6");
  failed |= require(tcl->slub_min_partial == 5,
                    "V643 min_partial must be 5");

  /* From every possible phase 0..7, eight one-free insertions include at
   * least one overflow. They do not normalize the final phase. */
  for (unsigned initial = 0; initial <= 7; initial++) {
    struct slub_model m = {0};
    for (unsigned i = 0; i < initial; i++)
      put_partial(&m, tcl->slub_cpu_partial, one_free(false));
    unsigned before = m.drains;
    for (unsigned i = 0; i < 8; i++)
      put_partial(&m, tcl->slub_cpu_partial, one_free(true));
    failed |= require(m.drains > before,
                      "eight insertions did not force a CPU-partial drain");
  }

  /* Sixteen controlled ballast insertions guarantee that at least one full
   * batch of seven reaches the node regardless of the initial phase. */
  for (unsigned initial = 0; initial <= 7; initial++) {
    struct slub_model m = {0};
    for (unsigned i = 0; i < initial; i++)
      put_partial(&m, tcl->slub_cpu_partial, one_free(false));
    for (unsigned i = 0; i < 16; i++)
      put_partial(&m, tcl->slub_cpu_partial, one_free(true));
    failed |= require(m.controlled_to_node >= 7,
                      "ballast did not establish min_partial safely");
  }

  /* With node ballast already present, an empty target on the CPU-partial
   * list is discarded within at most seven subsequent one-free insertions,
   * independent of the initial CPU-partial phase. */
  for (unsigned initial = 0; initial <= 7; initial++) {
    struct slub_model m = {.node_partial = tcl->slub_min_partial};
    for (unsigned i = 0; i < initial; i++)
      put_partial(&m, tcl->slub_cpu_partial, one_free(false));
    struct partial_page target = one_free(true);
    target.target = true;
    target.empty = true;
    put_partial(&m, tcl->slub_cpu_partial, target);
    for (unsigned i = 0; i < 7 && !m.target_discarded; i++)
      put_partial(&m, tcl->slub_cpu_partial, one_free(true));
    failed |= require(m.target_discarded,
                      "empty target was not discarded within seven pushes");
  }

  if (failed) return 1;
  puts("PASS: V643 SLUB model: ballast=16, min_partial=5, "
       "cpu_partial=6, target drain bound=7");
  return 0;
}
