#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int read_line(FILE *stream, char *line, size_t size) {
  if (!fgets(line, (int)size, stream)) return -1;
  fputs(line, stdout);
  return 0;
}

static int command(FILE *stream, const char *request, const char *needle) {
  if (fprintf(stream, "%s\n", request) < 0 || fflush(stream) != 0) return -1;
  char line[1024];
  int matched = 0;
  while (read_line(stream, line, sizeof(line)) == 0) {
    if (strstr(line, needle)) matched = 1;
    if (strcmp(line, "@@END@@\n") == 0) return matched ? 0 : -1;
  }
  return -1;
}

int main(int argc, char **argv) {
  const char *name = argc > 1 ? argv[1] : "tcl_root_proof";
  const char *expected_uid = argc > 2 ? argv[2] : "2000";
  const char *expected_broker_uid = argc > 3 ? argv[3] : "0";
  const char *expected_broker_gid = argc > 4 ? argv[4] : "0";
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 2;

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  size_t name_len = strlen(name);
  if (!name_len || name_len + 1 >= sizeof(address.sun_path)) return 3;
  address.sun_path[0] = '\0';
  memcpy(address.sun_path + 1, name, name_len);
  socklen_t address_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                      1 + name_len);

  int connected = 0;
  for (int attempt = 0; attempt < 1200; attempt++) {
    if (connect(fd, (struct sockaddr *)&address, address_len) == 0) {
      connected = 1;
      break;
    }
    if (errno != ECONNREFUSED && errno != ENOENT) return 4;
    usleep(100000);
  }
  if (!connected) return 5;

  FILE *stream = fdopen(fd, "r+");
  if (!stream) return 6;
  setvbuf(stream, NULL, _IOLBF, 0);

  char hello[1024];
  char hello_needle[128];
  int hello_len = snprintf(hello_needle, sizeof(hello_needle),
                           "SESSION uid=%s broker_uid=%s", expected_uid,
                           expected_broker_uid);
  if (hello_len < 0 || (size_t)hello_len >= sizeof(hello_needle)) return 7;
  if (read_line(stream, hello, sizeof(hello)) != 0 ||
      !strstr(hello, hello_needle) ||
      !strstr(hello, "selinux=1") ||
      !strstr(hello, "policycaps=11100100") ||
      !strstr(hello, "netlink=restored")) {
    fclose(stream);
    return 7;
  }
  char id_needle[160];
  int id_len = snprintf(id_needle, sizeof(id_needle),
                        "uid=%s euid=%s gid=%s egid=%s",
                        expected_broker_uid, expected_broker_uid,
                        expected_broker_gid, expected_broker_gid);
  if (id_len < 0 || (size_t)id_len >= sizeof(id_needle)) return 7;
  if (command(stream, "PING", "PONG") != 0 ||
      command(stream, "ID", id_needle) != 0 ||
      command(stream, "STOP", "STOPPING") != 0) {
    fclose(stream);
    return 8;
  }
  fclose(stream);
  puts("MINCLIENT PASS: root broker verified and stopped");
  return 0;
}
