#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int expect_line(FILE *stream, const char *needle) {
  char line[4096];
  if (!fgets(line, sizeof(line), stream)) return -1;
  fputs(line, stdout);
  return strstr(line, needle) ? 0 : -1;
}

static int command(FILE *stream, const char *request, const char *needle) {
  if (fprintf(stream, "%s\n", request) < 0 || fflush(stream) != 0) return -1;
  char line[4096];
  int matched = 0;
  while (fgets(line, sizeof(line), stream)) {
    fputs(line, stdout);
    if (strstr(line, needle)) matched = 1;
    if (strcmp(line, "@@END@@\n") == 0) return matched ? 0 : -1;
  }
  return -1;
}

static int response(FILE *stream, const char *needle) {
  char line[4096];
  int matched = 0;
  while (fgets(line, sizeof(line), stream)) {
    fputs(line, stdout);
    if (strstr(line, needle)) matched = 1;
    if (strcmp(line, "@@END@@\n") == 0) return matched ? 0 : -1;
  }
  return -1;
}

int main(int argc, char **argv) {
  const char *name = argc > 1 ? argv[1] : "tcl_root_broker_test";
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 2;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  size_t len = strlen(name);
  if (!len || len + 1 >= sizeof(addr.sun_path)) return 3;
  addr.sun_path[0] = '\0';
  memcpy(addr.sun_path + 1, name, len);
  socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + len);
  for (int i = 0; connect(fd, (struct sockaddr *)&addr, addr_len) != 0; i++) {
    /* QEMU TCG can spend several minutes in the two production reclaims. */
    if (i == 55000) {
      fprintf(stderr, "connect errno=%d\n", errno);
      return 4;
    }
    usleep(10000);
  }
  FILE *stream = fdopen(fd, "r+");
  if (!stream) return 5;
  setvbuf(stream, NULL, _IOLBF, 0);
  if (argc != 7) {
    fprintf(stderr, "usage: %s SOCKET HANDOFF PREFLIGHT KSUD MODULE STATUS\n",
            argv[0]);
    fclose(stream);
    return 6;
  }
  if (expect_line(stream, "PREAUTH") != 0 ||
      fprintf(stream, "HANDOFF\t%s\t%s\t%s\t%s\t%s\n",
              argv[2], argv[3], argv[4], argv[5], argv[6]) < 0 ||
      fflush(stream) != 0) {
    fclose(stream);
    return 6;
  }
#ifdef TCL_ANDROID_EXEC_TEST
  const char *exec_needle = "broker-exec-ok";
#else
  const char *exec_needle = "RC=127";
#endif
  if (expect_line(stream, "policycaps=11100100 netlink=restored") != 0 ||
      response(stream, "HANDOFF_READY=1") != 0 ||
      command(stream, "PING", "PONG") != 0 ||
      command(stream, "ID", "selinux=1") != 0 ||
      command(stream, "FS_LIST 2f", "ENTRY") != 0 ||
      command(stream, "FS_STAT 2f70726f632f76657273696f6e", "FS_STAT") != 0 ||
      command(stream, "FS_READ 2f70726f632f76657273696f6e", "DATA") != 0 ||
      command(stream, "FS_STAT 2f70726f632f6b636f7265", "FS_ERROR") != 0 ||
      /* The host harness intentionally has no /system/bin/sh. Receiving the
       * framed RC=127 response still proves the EXEC request path and keeps
       * Android-only command execution out of the host test. */
      command(stream, "EXEC printf broker-exec-ok", exec_needle) != 0 ||
      command(stream, "STOP", "STOPPING") != 0) {
    fclose(stream);
    return 6;
  }
  fclose(stream);
  return 0;
}
