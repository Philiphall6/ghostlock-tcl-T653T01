#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define EXPECTED_KERNEL "5.15.180-android14-11"
#define EXPECTED_FIRMWARE "V8-T653T01-LF1V643"
#define EXPECTED_MODULE_SHA \
  "b6aeb907bd468852a11d7a90d121df87e1716f3b9549c69ee0190607e0d5f50c"
#define EXPECTED_KSUD_SHA \
  "528c80259613a1e27a90d8f202fda33ecceba9c1fd42e1d807fdbbc859af5e68"
#define MAX_REPLY (128U * 1024U)
#ifndef EXPECTED_PEER_UID
#define EXPECTED_PEER_UID "2000"
#endif
#ifndef EXPECTED_BROKER_UID
#define EXPECTED_BROKER_UID "0"
#endif

static int safe_path(const char *path) {
  if (!path || strncmp(path, "/data/", 6) != 0) return 0;
  for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') || strchr("/._~+=-", *p))
      continue;
    return 0;
  }
  return strlen(path) < 512;
}

static int connect_abstract(const char *name) {
  size_t name_len = strlen(name);
  if (!name_len || name_len + 1 >= sizeof(((struct sockaddr_un *)0)->sun_path))
    return -1;

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  address.sun_path[0] = '\0';
  memcpy(address.sun_path + 1, name, name_len);
  socklen_t address_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                      1 + name_len);

  for (int attempt = 0; attempt < 600; attempt++) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&address, address_len) == 0) {
      struct timeval timeout = {.tv_sec = 70, .tv_usec = 0};
      (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout));
      (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       sizeof(timeout));
      return fd;
    }
    int saved = errno;
    close(fd);
    if (saved != ECONNREFUSED && saved != ENOENT && saved != EACCES) {
      errno = saved;
      return -1;
    }
    usleep(100000);
  }
  errno = ETIMEDOUT;
  return -1;
}

static int append_line(char *reply, size_t capacity, size_t *used,
                       const char *line) {
  size_t length = strlen(line);
  if (*used + length + 1 > capacity) return -1;
  memcpy(reply + *used, line, length);
  *used += length;
  reply[*used] = '\0';
  return 0;
}

static int command_collect(FILE *stream, const char *request,
                           char *reply, size_t capacity) {
  if (fprintf(stream, "%s\n", request) < 0 || fflush(stream) != 0) return -1;
  size_t used = 0;
  reply[0] = '\0';
  char line[4096];
  while (fgets(line, sizeof(line), stream)) {
    fputs(line, stdout);
    if (strcmp(line, "@@END@@\n") == 0) return 0;
    if (append_line(reply, capacity, &used, line) != 0) return -1;
  }
  return -1;
}

static int contains_all(const char *text, const char *const *needles,
                        size_t count) {
  for (size_t index = 0; index < count; index++)
    if (!strstr(text, needles[index])) return 0;
  return 1;
}

static int send_stop(FILE *stream) {
  char reply[4096];
  return command_collect(stream, "STOP", reply, sizeof(reply));
}

int main(int argc, char **argv) {
  if (argc != 5 || !safe_path(argv[2]) || !safe_path(argv[3]) ||
      !safe_path(argv[4])) {
    fprintf(stderr, "usage: %s ABSTRACT PREFLIGHT KSUD MODULE\n", argv[0]);
    return 2;
  }
  const char *name = argv[1];
  const char *preflight = argv[2];
  const char *ksud = argv[3];
  const char *module = argv[4];

  int fd = connect_abstract(name);
  if (fd < 0) {
    fprintf(stderr, "BROKER_CONNECT_FAILED errno=%d %s\n", errno,
            strerror(errno));
    return 3;
  }
  FILE *stream = fdopen(fd, "r+");
  if (!stream) {
    close(fd);
    return 4;
  }
  setvbuf(stream, NULL, _IOLBF, 0);

  char hello[2048];
  if (!fgets(hello, sizeof(hello), stream)) {
    fprintf(stderr, "BROKER_HELLO_FAILED errno=%d %s\n", errno,
            strerror(errno));
    fclose(stream);
    return 5;
  }
  fputs(hello, stdout);
  const char *const hello_needles[] = {
      "SESSION uid=" EXPECTED_PEER_UID " broker_uid=" EXPECTED_BROKER_UID,
      "selinux=1",
      "policycaps=11100100", "netlink=restored"};
  if (!contains_all(hello, hello_needles,
                    sizeof(hello_needles) / sizeof(hello_needles[0]))) {
    fprintf(stderr, "BROKER_HELLO_REFUSED\n");
    fclose(stream);
    return 6;
  }

  char *reply = calloc(1, MAX_REPLY);
  if (!reply) {
    fclose(stream);
    return 7;
  }
  if (command_collect(stream, "PING", reply, MAX_REPLY) != 0 ||
      !strstr(reply, "PONG") ||
      command_collect(stream, "ID", reply, MAX_REPLY) != 0) {
    free(reply);
    fclose(stream);
    return 8;
  }
  const char *const id_needles[] = {
      "uid=" EXPECTED_BROKER_UID, "euid=" EXPECTED_BROKER_UID,
      "gid=" EXPECTED_BROKER_UID, "egid=" EXPECTED_BROKER_UID,
      "selinux=1"};
  if (!contains_all(reply, id_needles,
                    sizeof(id_needles) / sizeof(id_needles[0]))) {
    (void)send_stop(stream);
    free(reply);
    fclose(stream);
    return 9;
  }

#ifdef TCL_CLIENT_TESTING
  int test_stop_ok = send_stop(stream) == 0;
  free(reply);
  fclose(stream);
  if (!test_stop_ok) return 9;
  puts("RESUKISU_CLIENT_PROTOCOL_TEST_PASS");
  return 0;
#endif

  char request[4096];
  int count = snprintf(
      request, sizeof(request),
      "EXEC echo CONTEXT=$(id -Z 2>/dev/null); echo ENFORCING=$(getenforce); "
      "echo KERNEL=$(uname -r); echo FW=$(getprop ro.software.version_id); "
      "echo AVB=$(getprop ro.boot.verifiedbootstate)/$(getprop ro.boot.vbmeta.device_state); "
      "echo MODULE_SHA=$(sha256sum %s 2>/dev/null | cut -d' ' -f1); "
      "echo KSUD_SHA=$(sha256sum %s 2>/dev/null | cut -d' ' -f1); "
      "%s; echo HELPER_RC=$?",
      module, ksud, preflight);
  if (count < 0 || (size_t)count >= sizeof(request) ||
      command_collect(stream, request, reply, MAX_REPLY) != 0) {
    (void)send_stop(stream);
    free(reply);
    fclose(stream);
    return 10;
  }
  char kernel_marker[128];
  char firmware_marker[128];
  char module_marker[96];
  char ksud_marker[96];
  snprintf(kernel_marker, sizeof(kernel_marker), "KERNEL=%s", EXPECTED_KERNEL);
  snprintf(firmware_marker, sizeof(firmware_marker), "FW=%s",
           EXPECTED_FIRMWARE);
  snprintf(module_marker, sizeof(module_marker), "MODULE_SHA=%s",
           EXPECTED_MODULE_SHA);
  snprintf(ksud_marker, sizeof(ksud_marker), "KSUD_SHA=%s",
           EXPECTED_KSUD_SHA);
  const char *const preflight_needles[] = {
      "PREFLIGHT_OK", "HELPER_RC=0", "ENFORCING=Enforcing",
      kernel_marker, firmware_marker, "AVB=green/locked", module_marker,
      ksud_marker, "RC=0",
      "EXEC_WINDOW=restored policycaps=11100100"};
  if (!contains_all(reply, preflight_needles,
                    sizeof(preflight_needles) / sizeof(preflight_needles[0]))) {
    puts("RESUKISU_PREFLIGHT_REFUSED");
    (void)send_stop(stream);
    free(reply);
    fclose(stream);
    return 11;
  }

  count = snprintf(request, sizeof(request),
                   "EXEC %s insmod %s allow_shell=1 2>&1; rc=$?; "
                   "echo LOAD_RC=$rc; grep '^kernelsu ' /proc/modules "
                   "2>/dev/null || true",
                   ksud, module);
  if (count < 0 || (size_t)count >= sizeof(request) ||
      command_collect(stream, request, reply, MAX_REPLY) != 0) {
    (void)send_stop(stream);
    free(reply);
    fclose(stream);
    return 12;
  }
  int loaded = strstr(reply, "LOAD_RC=0") && strstr(reply, "kernelsu ") &&
               strstr(reply, "RC=0") &&
               strstr(reply, "EXEC_WINDOW=restored policycaps=11100100") &&
               !strstr(reply, "TIMEOUT") &&
               !strstr(reply, "EXEC_WINDOW=FAILED");
  int stop_ok = send_stop(stream) == 0;
  free(reply);
  fclose(stream);
  if (!loaded || !stop_ok) {
    puts("RESUKISU_LOAD_FAILED");
    return 13;
  }
  puts("RESUKISU_CLIENT_PASS");
  return 0;
}
