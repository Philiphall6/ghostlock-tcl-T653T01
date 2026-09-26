#define _GNU_SOURCE

#include <errno.h>
#include <linux/io_uring.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  int failures = 0;
  int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
  printf("seccomp=%d\n", seccomp);

  struct perf_event_attr perf;
  memset(&perf, 0, sizeof(perf));
  perf.type = PERF_TYPE_SOFTWARE;
  perf.config = PERF_COUNT_SW_CPU_CLOCK;
  perf.size = sizeof(perf);
  perf.disabled = 1;
  errno = 0;
  int perf_fd = (int)syscall(__NR_perf_event_open, &perf, 0, -1, -1, 0);
  printf("perf_event_open=%d errno=%d\n", perf_fd, perf_fd < 0 ? errno : 0);
  if (perf_fd < 0) failures++;
  else close(perf_fd);

  struct io_uring_params uring;
  memset(&uring, 0, sizeof(uring));
  errno = 0;
  int uring_fd = (int)syscall(__NR_io_uring_setup, 2, &uring);
  printf("io_uring_setup=%d errno=%d\n", uring_fd,
         uring_fd < 0 ? errno : 0);
  if (uring_fd < 0) failures++;
  else close(uring_fd);

  errno = 0;
  int inet_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  printf("inet_dgram=%d errno=%d\n", inet_fd, inet_fd < 0 ? errno : 0);
  if (inet_fd < 0) failures++;
  else close(inet_fd);

  if (failures == 0) {
    puts("PREFLIGHT_OK");
    return 0;
  }
  printf("UNTRUSTED_APP_BLOCKED failures=%d\n", failures);
  return 10 + failures;
}
