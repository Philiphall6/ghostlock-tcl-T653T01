#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "tcl_v643/stack_geometry.h"
#include "tcl_v643/pselect_carrier.h"

/*
 * Safe host-only semantic check.  It does not exercise the futex bug or any
 * kernel address.  Representative 64-bit values are interpreted solely as
 * exceptfds bitmaps, while connected AF_UNIX sockets occupy the referenced
 * descriptor range.  A timeout proves that these bit patterns do not make
 * pselect return as writable/ready data would.
 */
int main(void) {
  int sv[2] = {-1, -1};
  fd_set readfds, writefds, exceptfds;
  struct tcl_v643_pselect_carrier carrier;
  const uint64_t representative_task = UINT64_C(0xffffff8001234000);
  const uint64_t representative_lock = UINT64_C(0xffffff8001234800);
  struct timespec timeout = {.tv_sec = 0, .tv_nsec = 50000000};
  int rc = 1;

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The exact TCL target and this bitmap model require little endian"
#endif

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    perror("socketpair");
    return 1;
  }

  tcl_v643_build_pselect_carrier(
      &carrier, representative_task, representative_lock, 3, 1);
  for (int fd = 128; fd < (int)TCL_V643_PSELECT_NFDS; fd++) {
    if (!tcl_v643_carrier_fd_selected(&carrier, (unsigned)fd)) continue;
    if (dup2(sv[0], fd) < 0) {
      perror("dup2");
      goto out;
    }
  }
  memset(&readfds, 0, sizeof(readfds));
  memset(&writefds, 0, sizeof(writefds));
  memset(&exceptfds, 0, sizeof(exceptfds));
  memcpy(&readfds, carrier.readfds, sizeof(carrier.readfds));
  memcpy(&writefds, carrier.writefds, sizeof(carrier.writefds));
  memcpy(&exceptfds, carrier.exceptfds, sizeof(carrier.exceptfds));

  errno = 0;
  int ret = pselect(TCL_V643_PSELECT_NFDS,
                    &readfds, &writefds, &exceptfds,
                    &timeout, NULL);
  if (ret != 0) {
    fprintf(stderr, "FAIL: pselect ret=%d errno=%d (%s)\n",
            ret, errno, strerror(errno));
    goto out;
  }

  puts("PASS: representative V643 exceptfds bitmap stayed blocked until timeout");
  rc = 0;

out:
  for (int fd = 128; fd < (int)TCL_V643_PSELECT_NFDS; fd++) {
    if (tcl_v643_carrier_fd_selected(&carrier, (unsigned)fd)) close(fd);
  }
  close(sv[0]);
  close(sv[1]);
  return rc;
}
