#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "resukisu_required_symbols.h"

#ifndef EXPECTED_RELEASE
#define EXPECTED_RELEASE "5.15.180-android14-11"
#endif

static int read_small(const char *path, char *buffer, size_t capacity) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t count = read(fd, buffer, capacity - 1);
  int saved = errno;
  close(fd);
  errno = saved;
  if (count < 0) return -1;
  buffer[count] = '\0';
  return 0;
}

static int write_value(const char *path, const char *value, size_t length) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t count = write(fd, value, length);
  int saved = errno;
  close(fd);
  errno = saved;
  return count == (ssize_t)length ? 0 : -1;
}

static void normalize_symbol(char *name) {
  char *suffix = strchr(name, '$');
  char *llvm = strstr(name, ".llvm.");
  if (!suffix || (llvm && llvm < suffix)) suffix = llvm;
  if (suffix) *suffix = '\0';
}

static int module_already_loaded(void) {
  FILE *stream = fopen("/proc/modules", "re");
  if (!stream) return -1;
  char line[1024];
  int found = 0;
  while (fgets(line, sizeof(line), stream)) {
    if (!strncmp(line, "kernelsu ", 9)) {
      found = 1;
      break;
    }
  }
  fclose(stream);
  return found;
}

int main(void) {
  if (getuid() != 0 || geteuid() != 0) {
    fprintf(stderr, "PREFLIGHT_FAIL uid=%u euid=%u\n", getuid(), geteuid());
    return 10;
  }

  struct utsname uts;
  memset(&uts, 0, sizeof(uts));
  int uname_rc = uname(&uts);
  if (uname_rc != 0 || strcmp(uts.release, EXPECTED_RELEASE)) {
    fprintf(stderr, "PREFLIGHT_FAIL kernel=%s expected=%s\n",
            uname_rc == 0 ? uts.release : "unavailable", EXPECTED_RELEASE);
    return 11;
  }

  char disabled[32] = {0};
  if (read_small("/proc/sys/kernel/modules_disabled", disabled,
                 sizeof(disabled)) != 0 || strtol(disabled, NULL, 10) != 0) {
    fprintf(stderr, "PREFLIGHT_FAIL modules_disabled=%s errno=%d\n",
            disabled[0] ? disabled : "unreadable", errno);
    return 12;
  }
  int loaded = module_already_loaded();
  if (loaded != 0) {
    fprintf(stderr, "PREFLIGHT_FAIL kernelsu_loaded=%d\n", loaded);
    return 13;
  }

  char original_kptr[32];
  if (read_small("/proc/sys/kernel/kptr_restrict", original_kptr,
                 sizeof(original_kptr)) != 0) {
    fprintf(stderr, "PREFLIGHT_FAIL kptr_read errno=%d\n", errno);
    return 14;
  }
  if (write_value("/proc/sys/kernel/kptr_restrict", "1", 1) != 0) {
    fprintf(stderr, "PREFLIGHT_FAIL kptr_set errno=%d\n", errno);
    return 15;
  }

  unsigned int *matches = calloc(RESUKISU_REQUIRED_SYMBOL_COUNT,
                                 sizeof(*matches));
  unsigned long long *addresses = calloc(RESUKISU_REQUIRED_SYMBOL_COUNT,
                                         sizeof(*addresses));
  if (!matches || !addresses) {
    write_value("/proc/sys/kernel/kptr_restrict", original_kptr,
                strlen(original_kptr));
    free(matches);
    free(addresses);
    return 16;
  }

  FILE *symbols = fopen("/proc/kallsyms", "re");
  if (!symbols) {
    int saved = errno;
    write_value("/proc/sys/kernel/kptr_restrict", original_kptr,
                strlen(original_kptr));
    fprintf(stderr, "PREFLIGHT_FAIL kallsyms_open errno=%d\n", saved);
    free(matches);
    free(addresses);
    return 17;
  }

  char line[1024];
  while (fgets(line, sizeof(line), symbols)) {
    unsigned long long address = 0;
    char type = '?';
    char name[768];
    char extra[8];
    int fields = sscanf(line, "%llx %c %767s %7s", &address, &type, name,
                        extra);
    if (fields != 3) continue; /* Ignore module-owned symbols. */
    normalize_symbol(name);
    for (size_t i = 0; i < RESUKISU_REQUIRED_SYMBOL_COUNT; i++) {
      if (!strcmp(name, resukisu_required_symbols[i])) {
        matches[i]++;
        if (address) addresses[i] = address;
      }
    }
  }
  fclose(symbols);
  int restore_rc = write_value("/proc/sys/kernel/kptr_restrict",
                               original_kptr, strlen(original_kptr));

  size_t resolved = 0;
  size_t missing = 0;
  size_t duplicate = 0;
  for (size_t i = 0; i < RESUKISU_REQUIRED_SYMBOL_COUNT; i++) {
    if (matches[i] == 1 && addresses[i] != 0) {
      resolved++;
    } else {
      if (matches[i] > 1) duplicate++;
      else missing++;
      if (missing + duplicate <= 20)
        fprintf(stderr, "SYMBOL_FAIL %s matches=%u address=%llx\n",
                resukisu_required_symbols[i], matches[i], addresses[i]);
    }
  }

  printf("PREFLIGHT_COUNTS required=%zu resolved=%zu missing=%zu duplicate=%zu\n",
         RESUKISU_REQUIRED_SYMBOL_COUNT, resolved, missing, duplicate);
  printf("KPTR_RESTORE=%s\n", restore_rc == 0 ? "OK" : "FAILED");
  free(matches);
  free(addresses);

  if (restore_rc != 0 || missing || duplicate) {
    fprintf(stderr, "PREFLIGHT_FAIL symbol_resolution\n");
    return 18;
  }
  printf("PREFLIGHT_OK kernel=%s symbols=%zu/%zu\n", EXPECTED_RELEASE,
         resolved, RESUKISU_REQUIRED_SYMBOL_COUNT);
  return 0;
}
