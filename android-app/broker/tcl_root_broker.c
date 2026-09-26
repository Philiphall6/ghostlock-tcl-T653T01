#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ABSTRACT "tcl_root_broker"
#define MAX_REQUEST 4096
#define MAX_RESPONSE 131072
#define MAX_FILE_PREVIEW 32768
#define MAX_SELINUX_POLICY (16U * 1024U * 1024U)
#define V643_SELINUX_POLICY_SIZE 1030054U
#define RESPONSE_END "\n@@END@@\n"
#define RESUKISU_MANAGER_PACKAGE "com.philiphall6.resukisu.tcl"

static volatile sig_atomic_t running = 1;

static const char *enforce_path(void) {
#ifdef TCL_BROKER_TESTING
  const char *path = getenv("TCL_BROKER_ENFORCE_FILE");
  if (path && path[0]) return path;
#endif
  return "/sys/fs/selinux/enforce";
}

static void stop_handler(int sig) {
  (void)sig;
  running = 0;
}

static int write_all(int fd, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

static int read_selinux(void) {
  char c = '?';
  int fd = open(enforce_path(), O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    if (read(fd, &c, 1) != 1) c = '?';
    close(fd);
  }
  return c;
}

static int restore_enforcing(void) {
  if (read_selinux() == '1') return 0;
  int fd = open(enforce_path(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n = write(fd, "1", 1);
  int saved = errno;
  close(fd);
  errno = saved;
  if (n != 1) return -1;
  for (int i = 0; i < 100; i++) {
    if (read_selinux() == '1') return 0;
    usleep(10000);
  }
  errno = EIO;
  return -1;
}

static int enter_permissive(void) {
  if (read_selinux() == '0') return 0;
  if (read_selinux() != '1') {
    errno = EIO;
    return -1;
  }
  int fd = open(enforce_path(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n = write(fd, "0", 1);
  int saved = errno;
  close(fd);
  errno = saved;
  if (n != 1) return -1;
  for (int i = 0; i < 100; i++) {
    if (read_selinux() == '0') return 0;
    usleep(10000);
  }
  errno = EIO;
  return -1;
}

static const char *selinux_policy_path(void) {
#ifdef TCL_BROKER_TESTING
  const char *path = getenv("TCL_BROKER_POLICY_FILE");
  if (path && path[0]) return path;
#endif
  /* Do not use /sys/fs/selinux/policy here.  The 5.15 policydb writer omits
   * POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE and ..._GETNEIGH when exporting
   * the live policy, so loading that serialization drops TCL networking.
   * This file is the exact combined policy loaded at boot from the verified,
   * read-only V643 vendor partition. */
  return "/vendor/etc/selinux/precompiled_sepolicy";
}

static const char *selinux_load_path(void) {
#ifdef TCL_BROKER_TESTING
  const char *path = getenv("TCL_BROKER_LOAD_FILE");
  if (path && path[0]) return path;
#endif
  return "/sys/fs/selinux/load";
}

static const char *selinux_policycap_dir(void) {
#ifdef TCL_BROKER_TESTING
  const char *path = getenv("TCL_BROKER_POLICYCAP_DIR");
  if (path && path[0]) return path;
  return NULL;
#else
  return "/sys/fs/selinux/policy_capabilities";
#endif
}

static uint32_t load_le32(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int verify_v643_policy_header(const unsigned char *policy,
                                     size_t size) {
  /* Exact V643 binary-policy identity guard.  The supervising runner also
   * verifies SHA-256 1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851f
   * e001fd690b069819 before opening the root window. */
  const uint32_t policy_magic = 0xf97cff8cU;
  const uint32_t policy_version = 30U;
  const uint32_t policy_config = 0xc0000001U;
  const uint32_t android_netlink_route = 0x80000000U;
  const uint32_t android_netlink_getneigh = 0x40000000U;
  static const unsigned char target[] = "SE Linux";
  if (size != V643_SELINUX_POLICY_SIZE || load_le32(policy) != policy_magic) {
    errno = EINVAL;
    return -1;
  }
  uint32_t target_len = load_le32(policy + 4);
  size_t version_offset = 8U + (size_t)target_len;
  if (target_len != sizeof(target) - 1 ||
      memcmp(policy + 8, target, sizeof(target) - 1) != 0 ||
      version_offset + 8 > size) {
    errno = EINVAL;
    return -1;
  }
  uint32_t version = load_le32(policy + version_offset);
  uint32_t config = load_le32(policy + version_offset + 4);
  uint32_t required = android_netlink_route | android_netlink_getneigh;
  if (version != policy_version || config != policy_config ||
      (config & required) != required) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int read_small_value(const char *path, int *value) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  char byte = '?';
  ssize_t n = read(fd, &byte, 1);
  int saved = errno;
  close(fd);
  errno = saved;
  if (n != 1 || (byte != '0' && byte != '1')) {
    errno = EIO;
    return -1;
  }
  *value = byte - '0';
  return 0;
}

static int verify_v643_policycaps(void) {
  static const struct {
    const char *name;
    int expected;
  } caps[] = {
      {"network_peer_controls", 1},
      {"open_perms", 1},
      {"extended_socket_class", 1},
      {"always_check_network", 0},
      {"cgroup_seclabel", 0},
      {"nnp_nosuid_transition", 1},
      {"genfs_seclabel_symlinks", 0},
      {"ioctl_skip_cloexec", 0},
  };
  const char *dir = selinux_policycap_dir();
  if (!dir) return 0;
  for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, caps[i].name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
      errno = ENAMETOOLONG;
      return -1;
    }
    int actual = -1;
    if (read_small_value(path, &actual) != 0) return -1;
    if (actual != caps[i].expected) {
      errno = EPROTO;
      return -1;
    }
  }
  return 0;
}

/* The preserving rb_erase store deliberately keeps initialized non-zero,
 * but its pointer bytes temporarily replace policycap[0..4].  Re-enabling
 * enforcement before repairing those bytes can enable always_check_network
 * and cgroup_seclabel and cut both Ethernet and Wi-Fi.  Reloading the exact
 * immutable V643 boot policy is the supported kernel path that atomically
 * restores all policy capabilities plus android_netlink_route/getneigh. */
static int restore_network_policy_state(void) {
  int source = open(selinux_policy_path(), O_RDONLY | O_CLOEXEC);
  if (source < 0) return -1;
  size_t capacity = 2U * 1024U * 1024U;
  unsigned char *policy = malloc(capacity);
  if (!policy) {
    close(source);
    return -1;
  }
  size_t used = 0;
  for (;;) {
    if (used == capacity) {
      if (capacity >= MAX_SELINUX_POLICY) {
        errno = EFBIG;
        free(policy);
        close(source);
        return -1;
      }
      size_t next_capacity = capacity * 2;
      if (next_capacity > MAX_SELINUX_POLICY)
        next_capacity = MAX_SELINUX_POLICY;
      unsigned char *larger = realloc(policy, next_capacity);
      if (!larger) {
        free(policy);
        close(source);
        return -1;
      }
      policy = larger;
      capacity = next_capacity;
    }
    ssize_t n = read(source, policy + used, capacity - used);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      int saved = errno;
      free(policy);
      close(source);
      errno = saved;
      return -1;
    }
    if (n == 0) break;
    used += (size_t)n;
  }
  close(source);
  if (verify_v643_policy_header(policy, used) != 0) {
    free(policy);
    return -1;
  }

  int flags = O_WRONLY | O_CLOEXEC;
#ifdef TCL_BROKER_TESTING
  flags |= O_TRUNC;
#endif
  int load = open(selinux_load_path(), flags);
  if (load < 0) {
    free(policy);
    return -1;
  }
  ssize_t written;
  do {
    written = write(load, policy, used);
  } while (written < 0 && errno == EINTR);
  int saved = errno;
  close(load);
  free(policy);
  errno = saved;
  if (written < 0 || (size_t)written != used) {
    if (written >= 0) errno = EIO;
    return -1;
  }
  return verify_v643_policycaps();
}

static int close_permissive_window(void) {
  if (read_selinux() != '1') {
    if (restore_network_policy_state() != 0) return -1;
    if (restore_enforcing() != 0) return -1;
  }
  if (read_selinux() != '1') {
    errno = EIO;
    return -1;
  }
  return verify_v643_policycaps();
}

static long monotonic_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void sleep_for_ms(int delay_ms) {
  struct timespec remaining = {
      .tv_sec = delay_ms / 1000,
      .tv_nsec = (long)(delay_ms % 1000) * 1000000L,
  };
  while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {
  }
}

static void write_watchdog_marker(const char *stage, int delay_ms,
                                  int error_number) {
#ifdef TCL_BROKER_TESTING
  const char *path = getenv("TCL_BROKER_WATCHDOG_FILE");
  if (!path || !path[0]) return;
#else
  const char *path = "/data/local/tmp/.tcl_root_broker_watchdog";
#endif
  int marker_flags = O_WRONLY | O_CREAT | O_CLOEXEC;
  marker_flags |= (strcmp(stage, "armed") == 0 ||
                   strcmp(stage, "parked-no-reboot") == 0)
                      ? O_TRUNC
                      : O_APPEND;
  int fd = open(path, marker_flags, 0644);
  if (fd < 0) return;
  /* main() uses umask(077), but the ADB supervisor must be able to read this
   * non-secret state marker after SELinux has returned to enforcing. */
  (void)fchmod(fd, 0644);
  char marker[192];
  int n = snprintf(marker, sizeof(marker),
                   "stage=%s pid=%d delay_ms=%d selinux=%c errno=%d\n",
                   stage, getpid(), delay_ms, read_selinux(), error_number);
  if (n > 0) {
    size_t len = (size_t)n < sizeof(marker) ? (size_t)n : sizeof(marker) - 1;
    (void)write_all(fd, marker, len);
    (void)fsync(fd);
  }
  close(fd);
}

static int read_heartbeat_token(const char *path, char *out, size_t cap) {
  if (!path || !path[0] || !out || cap < 2) {
    errno = EINVAL;
    return -1;
  }
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n;
  do {
    n = read(fd, out, cap - 1);
  } while (n < 0 && errno == EINTR);
  int saved = errno;
  close(fd);
  errno = saved;
  if (n <= 0) return -1;
  out[n] = 0;
  return 0;
}

/* Optional, explicitly armed ADB-loss fail-safe.  The supervising Mint
 * process continuously changes heartbeat_file over its existing ADB
 * transport.  After the root session has safely restored policy/network and
 * enforcing, the broker waits for disarm_file.  If the heartbeat stops first,
 * the broker can reboot locally even though ADB itself is no longer usable.
 * With neither environment variable set this guard is completely disabled. */
static int monitor_adb_heartbeat(void) {
  const char *heartbeat_file = getenv("TCL_BROKER_ADB_HEARTBEAT_FILE");
  const char *disarm_file = getenv("TCL_BROKER_ADB_DISARM_FILE");
  const char *timeout_text = getenv("TCL_BROKER_ADB_HEARTBEAT_TIMEOUT_MS");
  int have_heartbeat = heartbeat_file && heartbeat_file[0];
  int have_disarm = disarm_file && disarm_file[0];
  if (!have_heartbeat && !have_disarm) return 0;
  if (!have_heartbeat || !have_disarm) {
    errno = EINVAL;
    write_watchdog_marker("adb-heartbeat-config-invalid", 0, errno);
    return -1;
  }
#ifndef TCL_BROKER_TESTING
  static const char prefix[] = "/data/local/tmp/";
  if (strncmp(heartbeat_file, prefix, sizeof(prefix) - 1) != 0 ||
      strncmp(disarm_file, prefix, sizeof(prefix) - 1) != 0 ||
      strstr(heartbeat_file, "..") || strstr(disarm_file, "..")) {
    errno = EINVAL;
    write_watchdog_marker("adb-heartbeat-config-invalid", 0, errno);
    return -1;
  }
#endif
  long timeout_ms = 30000;
  if (timeout_text && timeout_text[0]) {
    char *end = NULL;
    long parsed = strtol(timeout_text, &end, 10);
#ifdef TCL_BROKER_TESTING
    const long minimum = 250;
#else
    const long minimum = 10000;
#endif
    if (!end || *end || parsed < minimum || parsed > 300000) {
      errno = EINVAL;
      write_watchdog_marker("adb-heartbeat-config-invalid", 0, errno);
      return -1;
    }
    timeout_ms = parsed;
  }

  char previous[128] = {0};
  char current[128] = {0};
  long last_change = monotonic_ms();
  if (read_heartbeat_token(heartbeat_file, previous, sizeof(previous)) != 0)
    previous[0] = 0;
  write_watchdog_marker("adb-heartbeat-armed", (int)timeout_ms, 0);

  for (;;) {
    if (access(disarm_file, F_OK) == 0) {
      write_watchdog_marker("adb-heartbeat-disarmed", 0, 0);
      return 0;
    }
    if (read_heartbeat_token(heartbeat_file, current, sizeof(current)) == 0 &&
        strcmp(current, previous) != 0) {
      snprintf(previous, sizeof(previous), "%s", current);
      last_change = monotonic_ms();
    }
    long now = monotonic_ms();
    if (now - last_change >= timeout_ms) {
      errno = ETIMEDOUT;
      write_watchdog_marker("adb-heartbeat-expired", (int)timeout_ms, errno);
      return -1;
    }
    sleep_for_ms(250);
  }
}

/* Used only after a failed policy/network or enforcing restoration.  A
 * successful session must never reboot automatically. */
static void watchdog_reboot_or_park(int delay_ms, int enforce_rc) {
  write_watchdog_marker("armed", delay_ms, enforce_rc == 0 ? 0 : errno);
  sleep_for_ms(delay_ms);
  write_watchdog_marker("rebooting", delay_ms, 0);
  sync();
#ifdef TCL_BROKER_TESTING
  return;
#else
  if (reboot(RB_AUTOBOOT) == 0) return;
  int saved = errno;
  write_watchdog_marker("reboot-failed-parked", delay_ms, saved);
  signal(SIGTERM, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  for (;;) sleep_for_ms(3600000);
#endif
}

/* On success, retain both the normalized broker's descriptor references and
 * the raw W2 holder until a later manual reboot.  STOP closes the command
 * socket, but it does not reboot the television and does not tear down the
 * pinned credential backing page asynchronously. */
static int park_after_success(void) {
  write_watchdog_marker("parked-no-reboot", 0, 0);
  if (monitor_adb_heartbeat() != 0) {
    int saved = errno;
    write_watchdog_marker("adb-heartbeat-rebooting", 0, saved);
    sync();
#ifdef TCL_BROKER_TESTING
    errno = saved;
    return -1;
#else
    if (reboot(RB_AUTOBOOT) == 0) return 0;
    saved = errno;
    write_watchdog_marker("adb-heartbeat-reboot-failed-parked", 0, saved);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    for (;;) sleep_for_ms(3600000);
#endif
  }
#ifdef TCL_BROKER_TESTING
  const char *test_park = getenv("TCL_BROKER_TEST_PARK");
  if (!test_park || strcmp(test_park, "1") != 0) return 0;
#endif
  signal(SIGTERM, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  for (;;) sleep_for_ms(3600000);
}

static size_t appendf(char *out, size_t cap, size_t used,
                      const char *format, ...) {
  if (used >= cap) return cap;
  va_list args;
  va_start(args, format);
  int n = vsnprintf(out + used, cap - used, format, args);
  va_end(args);
  if (n < 0) return used;
  if ((size_t)n >= cap - used) return cap;
  return used + (size_t)n;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int decode_hex_path(const char *hex, char *path, size_t cap) {
  size_t n = strlen(hex);
  if (!n || (n & 1) || n / 2 >= cap) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 0; i < n; i += 2) {
    int hi = hex_nibble(hex[i]);
    int lo = hex_nibble(hex[i + 1]);
    if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) {
      errno = EINVAL;
      return -1;
    }
    path[i / 2] = (char)((hi << 4) | lo);
  }
  path[n / 2] = '\0';
  if (path[0] != '/') {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

static int path_has_prefix(const char *path, const char *prefix) {
  size_t n = strlen(prefix);
  return strncmp(path, prefix, n) == 0 &&
         (path[n] == '\0' || path[n] == '/');
}

/* The explorer is deliberately read-only and cannot inspect secrets whose
 * disclosure could damage DRM, device identity, user credentials or later
 * forensic conclusions.  realpath() is applied before this check so a symlink
 * cannot escape the deny list. */
static int path_is_sensitive(const char *path) {
  static const char *const denied[] = {
      "/dev/block", "/dev/mem", "/dev/kmem",
      "/sys/fs/selinux",
      "/data/adb", "/data/data", "/data/user", "/data/user_de",
      "/data/system", "/data/misc/keystore", "/data/misc/keystore-user",
      "/data/misc/keychain", "/data/misc/gatekeeper",
      "/data/misc/credstore", "/data/vendor/mediadrm",
      "/data/vendor/drm", "/data/vendor/widevine", "/data/vendor/tee",
      "/data/vendor/keymaster", "/data/vendor/secure_storage",
      "/mnt/vendor/persist", "/persist", "/metadata",
  };
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
    if (path_has_prefix(path, denied[i])) return 1;

  if (path_has_prefix(path, "/proc")) {
    const char *base = strrchr(path, '/');
    if ((base && (!strcmp(base, "/mem") || !strcmp(base, "/pagemap") ||
                  !strcmp(base, "/clear_refs") || !strcmp(base, "/keys") ||
                  !strcmp(base, "/kcore"))) ||
        strstr(path, "/fd/") || strstr(path, "/fdinfo/"))
      return 1;
  }
  return 0;
}

static int resolve_read_path(const char *hex, char *resolved, size_t cap) {
  char requested[PATH_MAX];
  if (decode_hex_path(hex, requested, sizeof(requested)) != 0) return -1;
  char canonical[PATH_MAX];
  if (!realpath(requested, canonical)) return -1;
  if (path_is_sensitive(canonical)) {
    errno = EACCES;
    return -1;
  }
  if (strlen(canonical) >= cap) {
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(resolved, canonical);
  return 0;
}

static void hex_encode(const unsigned char *src, size_t len, char *dst) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    dst[i * 2] = digits[src[i] >> 4];
    dst[i * 2 + 1] = digits[src[i] & 15];
  }
  dst[len * 2] = '\0';
}

static char mode_type(mode_t mode) {
  if (S_ISDIR(mode)) return 'd';
  if (S_ISREG(mode)) return 'f';
  if (S_ISLNK(mode)) return 'l';
  if (S_ISCHR(mode)) return 'c';
  if (S_ISBLK(mode)) return 'b';
  if (S_ISFIFO(mode)) return 'p';
  if (S_ISSOCK(mode)) return 's';
  return '?';
}

static size_t fs_list(const char *hex, char *out, size_t cap) {
  char path[PATH_MAX];
  if (resolve_read_path(hex, path, sizeof(path)) != 0)
    return (size_t)snprintf(out, cap, "FS_ERROR LIST errno=%d %s\n", errno,
                            strerror(errno));
  DIR *dir = opendir(path);
  if (!dir)
    return (size_t)snprintf(out, cap, "FS_ERROR LIST errno=%d %s\n", errno,
                            strerror(errno));

  size_t used = (size_t)snprintf(out, cap, "FS_LIST\t%s\n", path);
  int entries = 0;
  int truncated = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    struct stat st;
    if (fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
      continue;
    size_t name_len = strlen(entry->d_name);
    char name_hex[NAME_MAX * 2 + 1];
    if (name_len > NAME_MAX) continue;
    hex_encode((const unsigned char *)entry->d_name, name_len, name_hex);
    size_t before = used;
    used = appendf(out, cap, used, "ENTRY\t%c\t%04o\t%u\t%u\t%lld\t%s\n",
                   mode_type(st.st_mode), (unsigned)(st.st_mode & 07777),
                   (unsigned)st.st_uid, (unsigned)st.st_gid,
                   (long long)st.st_size, name_hex);
    if (used >= cap || used == before) {
      truncated = 1;
      break;
    }
    entries++;
    if (entries >= 512) {
      truncated = 1;
      break;
    }
  }
  closedir(dir);
  if (used >= cap) used = cap - 1;
  used = appendf(out, cap, used, "FS_END\t%d\ttruncated=%d\n", entries,
                 truncated);
  if (used >= cap) used = cap - 1;
  out[used] = '\0';
  return used;
}

static size_t fs_stat(const char *hex, char *out, size_t cap) {
  char path[PATH_MAX];
  if (resolve_read_path(hex, path, sizeof(path)) != 0)
    return (size_t)snprintf(out, cap, "FS_ERROR STAT errno=%d %s\n", errno,
                            strerror(errno));
  struct stat st;
  if (stat(path, &st) != 0)
    return (size_t)snprintf(out, cap, "FS_ERROR STAT errno=%d %s\n", errno,
                            strerror(errno));
  return (size_t)snprintf(out, cap,
                          "FS_STAT\t%c\t%04o\t%u\t%u\t%lld\t%lld\t%s\n",
                          mode_type(st.st_mode), (unsigned)(st.st_mode & 07777),
                          (unsigned)st.st_uid, (unsigned)st.st_gid,
                          (long long)st.st_size, (long long)st.st_mtime, path);
}

static size_t fs_read(const char *hex, char *out, size_t cap) {
  char path[PATH_MAX];
  if (resolve_read_path(hex, path, sizeof(path)) != 0)
    return (size_t)snprintf(out, cap, "FS_ERROR READ errno=%d %s\n", errno,
                            strerror(errno));
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return (size_t)snprintf(out, cap, "FS_ERROR READ errno=%d %s\n", errno,
                            strerror(errno));
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    int saved = errno ? errno : EISDIR;
    close(fd);
    return (size_t)snprintf(out, cap, "FS_ERROR READ errno=%d %s\n", saved,
                            strerror(saved));
  }
  unsigned char data[MAX_FILE_PREVIEW];
  size_t total = 0;
  while (total < sizeof(data)) {
    ssize_t n = read(fd, data + total, sizeof(data) - total);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    total += (size_t)n;
  }
  close(fd);
  int truncated = st.st_size > (off_t)total || total == sizeof(data);
  size_t used = (size_t)snprintf(out, cap,
      "FS_FILE\t%lld\t%zu\ttruncated=%d\t%s\nDATA\t",
      (long long)st.st_size, total, truncated, path);
  if (used + total * 2 + 2 >= cap)
    return (size_t)snprintf(out, cap, "FS_ERROR READ response-too-large\n");
  hex_encode(data, total, out + used);
  used += total * 2;
  out[used++] = '\n';
  out[used] = '\0';
  return used;
}

static size_t run_command(const char *command, char *out, size_t cap) {
  int p[2];
  if (pipe2(p, O_CLOEXEC) != 0)
    return (size_t)snprintf(out, cap, "ERROR pipe errno=%d\n", errno);

  /* The W2 child deliberately retains the kernel SID.  Under the restored
   * production policy that SID cannot execute /system/bin/sh, even though
   * the process has uid 0, so execve() otherwise exits 127.  The immutable
   * V643 policy and its network policycaps have already been restored before
   * an authorized client reaches this point.  Temporarily disable only
   * enforcement for the bounded child command; do not reload or modify the
   * policy.  Enforcement and all policycaps are re-checked before replying.
   *
   * This is intentionally scoped to the single authenticated broker stream.
   * A timeout is ten seconds and every error path below restores enforcing. */
  if (read_selinux() != '1' || verify_v643_policycaps() != 0) {
    int saved = errno ? errno : EPROTO;
    close(p[0]);
    close(p[1]);
    errno = saved;
    return (size_t)snprintf(out, cap,
                            "ERROR exec-window-precheck errno=%d selinux=%c\n",
                            errno, read_selinux());
  }
  if (enter_permissive() != 0) {
    int saved = errno;
    close(p[0]);
    close(p[1]);
    errno = saved;
    return (size_t)snprintf(out, cap,
                            "ERROR exec-window-open errno=%d selinux=%c\n",
                            errno, read_selinux());
  }

  pid_t child = fork();
  if (child == 0) {
    setpgid(0, 0);
    dup2(p[1], STDOUT_FILENO);
    dup2(p[1], STDERR_FILENO);
    close(p[0]);
    close(p[1]);
    execl("/system/bin/sh", "sh", "-c", command, (char *)NULL);
    _exit(127);
  }
  close(p[1]);
  if (child < 0) {
    int saved = errno;
    close(p[0]);
    int restore_rc = restore_enforcing();
    int restore_errno = errno;
    errno = saved;
    return (size_t)snprintf(
        out, cap,
        "ERROR fork errno=%d restore=%s restore_errno=%d selinux=%c\n",
        saved, restore_rc == 0 ? "ok" : "failed", restore_errno,
        read_selinux());
  }

  size_t used = 0;
  long deadline = monotonic_ms() + 10000;
  int timed_out = 0;
  while (used + 1 < cap) {
    long remain = deadline - monotonic_ms();
    if (remain <= 0) {
      timed_out = 1;
      break;
    }
    struct pollfd f = {.fd = p[0], .events = POLLIN | POLLHUP};
    int pr = poll(&f, 1, remain > 250 ? 250 : (int)remain);
    if (pr < 0 && errno == EINTR) continue;
    if (pr < 0) break;
    if (pr == 0) continue;
    ssize_t n = read(p[0], out + used, cap - used - 1);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    used += (size_t)n;
  }
  close(p[0]);

  int status = 0;
  if (timed_out) {
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
  }
  waitpid(child, &status, 0);
  int restore_rc = restore_enforcing();
  int restore_errno = errno;
  int caps_rc = restore_rc == 0 ? verify_v643_policycaps() : -1;
  int caps_errno = errno;
  if (used + 64 < cap) {
    if (timed_out)
      used += (size_t)snprintf(out + used, cap - used, "\nTIMEOUT\n");
    else if (WIFEXITED(status))
      used += (size_t)snprintf(out + used, cap - used, "\nRC=%d\n",
                               WEXITSTATUS(status));
    else
      used += (size_t)snprintf(out + used, cap - used, "\nSIGNAL=%d\n",
                               WIFSIGNALED(status) ? WTERMSIG(status) : -1);
  }
  if (used + 160 < cap) {
    if (restore_rc == 0 && caps_rc == 0 && read_selinux() == '1') {
      used += (size_t)snprintf(out + used, cap - used,
                               "EXEC_WINDOW=restored policycaps=11100100\n");
    } else {
      used += (size_t)snprintf(
          out + used, cap - used,
          "EXEC_WINDOW=FAILED restore_errno=%d caps_errno=%d selinux=%c\n",
          restore_errno, caps_errno, read_selinux());
    }
  }
  out[used] = '\0';
  return used;
}

static int bootstrap_path_ok(const char *path, int status_path) {
  if (!path || path[0] != '/' || strlen(path) >= PATH_MAX - 64 ||
      strstr(path, "/../") || strstr(path, "/./") || strstr(path, "//"))
    return 0;
  for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') || strchr("/._~+=-", *p))
      continue;
    return 0;
  }
#ifdef TCL_BROKER_TESTING
  (void)status_path;
  return 1;
#else
  if (status_path)
    return strncmp(path, "/data/local/tmp/.tcl_resukisu_", 32) == 0;
  return strncmp(path, "/data/app/", 10) == 0;
#endif
}

static int wait_child_bounded(pid_t child, int timeout_ms) {
  long deadline = monotonic_ms() + timeout_ms;
  int status = 0;
  for (;;) {
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) {
      if (WIFEXITED(status)) return WEXITSTATUS(status);
      if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
      return 125;
    }
    if (waited < 0 && errno != EINTR) return 126;
    if (monotonic_ms() >= deadline) {
      kill(-child, SIGKILL);
      kill(child, SIGKILL);
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
      }
      return 124;
    }
    sleep_for_ms(20);
  }
}

static int run_resukisu_handoff(const char *handoff, const char *preflight,
                                const char *ksud, const char *module,
                                const char *status_path) {
  if (!bootstrap_path_ok(handoff, 0) ||
      !bootstrap_path_ok(preflight, 0) ||
      !bootstrap_path_ok(ksud, 0) || !bootstrap_path_ok(module, 0) ||
      !bootstrap_path_ok(status_path, 1) || access(handoff, X_OK) != 0 ||
      access(preflight, X_OK) != 0 || access(ksud, X_OK) != 0 ||
      access(module, R_OK) != 0) {
    errno = EINVAL;
    return 123;
  }
  (void)unlink(status_path);
  int completion[2];
  if (pipe(completion) != 0) return 126;
  pid_t child = fork();
  if (child == 0) {
    setpgid(0, 0);
    close(completion[0]);
    char completion_text[32];
    snprintf(completion_text, sizeof(completion_text), "%d", completion[1]);
    char *const argv[] = {
        (char *)handoff, "--direct-child", "--preflight", (char *)preflight,
        "--ksud", (char *)ksud, "--module", (char *)module,
        "--status", (char *)status_path, "--completion-fd", completion_text,
        "--package-name", RESUKISU_MANAGER_PACKAGE, NULL};
    execv(handoff, argv);
    _exit(127);
  }
  close(completion[1]);
  close(completion[0]);
  if (child < 0) return 126;
  return wait_child_bounded(child, 90000);
}

static size_t read_bootstrap_status(const char *path, char *out, size_t cap) {
  if (!bootstrap_path_ok(path, 1) || cap < 2) return 0;
  for (int attempt = 0; attempt < 150; attempt++) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
      ssize_t n = read(fd, out, cap - 1);
      close(fd);
      if (n > 0) {
        out[n] = '\0';
        if (strstr(out, "state=READY") || strstr(out, "state=FAILED") ||
            attempt == 149)
          return (size_t)n;
      }
    }
    sleep_for_ms(100);
  }
  out[0] = '\0';
  return 0;
}

static int parse_handoff_request(char *request, char **handoff,
                                 char **preflight, char **ksud,
                                 char **module, char **status_path) {
  static const char prefix[] = "HANDOFF\t";
  if (strncmp(request, prefix, sizeof(prefix) - 1) != 0) return -1;
  char *save = NULL;
  char *fields[5];
  char *cursor = request + sizeof(prefix) - 1;
  for (size_t i = 0; i < 5; i++) {
    fields[i] = strtok_r(i == 0 ? cursor : NULL, "\t", &save);
    if (!fields[i] || !fields[i][0]) return -1;
  }
  if (strtok_r(NULL, "\t", &save) != NULL) return -1;
  if (!bootstrap_path_ok(fields[0], 0) ||
      !bootstrap_path_ok(fields[1], 0) ||
      !bootstrap_path_ok(fields[2], 0) ||
      !bootstrap_path_ok(fields[3], 0) ||
      !bootstrap_path_ok(fields[4], 1))
    return -1;
  *handoff = fields[0];
  *preflight = fields[1];
  *ksud = fields[2];
  *module = fields[3];
  *status_path = fields[4];
  return 0;
}

static int write_response_end(int client) {
  return write_all(client, RESPONSE_END, sizeof(RESPONSE_END) - 1);
}

/* Return 1 for a rejected peer and 0 after the authorized session ends. */
static int serve_client(int client, uid_t allowed_uid) {
  struct ucred peer;
  socklen_t peer_len = sizeof(peer);
  if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
      peer_len != sizeof(peer) || peer.uid != allowed_uid) {
    static const char denied[] = "DENIED peer uid\n";
    write_all(client, denied, sizeof(denied) - 1);
    return 1;
  }

  /* The ADB-shell client is started before GhostLock and wins this one-shot
   * socket only after SO_PEERCRED proves uid 2000.  ReSukiSU remains a
   * separate component: the authenticated client must explicitly request
   * its signed handoff worker.  That worker has to be execve()'d while the
   * already-existing GhostLock permissive window is open; once enforcing is
   * restored, the kernel SID cannot execute Android files (errno EACCES).
   * Policy/network restoration is mandatory before any result is returned. */
  if (read_selinux() != '0') {
    static const char wrong_state[] =
        "FATAL bootstrap requires existing permissive window\n";
    write_all(client, wrong_state, sizeof(wrong_state) - 1);
    return 0;
  }
  char preauth[160];
  int preauth_len = snprintf(preauth, sizeof(preauth),
                             "PREAUTH uid=%u broker_uid=%u pid=%d selinux=0\n",
                             allowed_uid, geteuid(), getpid());
  if (write_all(client, preauth, (size_t)preauth_len) != 0) return 0;

  struct timeval bootstrap_timeout = {.tv_sec = 10, .tv_usec = 0};
  (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &bootstrap_timeout,
                   sizeof(bootstrap_timeout));
  char bootstrap_request[MAX_REQUEST];
  ssize_t bootstrap_count;
  do {
    bootstrap_count = read(client, bootstrap_request,
                           sizeof(bootstrap_request) - 1);
  } while (bootstrap_count < 0 && errno == EINTR);
  if (bootstrap_count <= 0) {
    (void)close_permissive_window();
    return 0;
  }
  bootstrap_request[bootstrap_count] = '\0';
  char *bootstrap_eol = strpbrk(bootstrap_request, "\r\n");
  if (bootstrap_eol) *bootstrap_eol = '\0';
  char *handoff = NULL;
  char *preflight = NULL;
  char *ksud = NULL;
  char *module = NULL;
  char *status_path = NULL;
  int handoff_rc = 122;
  if (parse_handoff_request(bootstrap_request, &handoff, &preflight, &ksud,
                            &module, &status_path) == 0) {
    handoff_rc = run_resukisu_handoff(handoff, preflight, ksud, module,
                                      status_path);
  }

  int restore_rc = close_permissive_window();
  int restore_errno = errno;
  if (restore_rc != 0) {
    char fatal[256];
    int n = snprintf(fatal, sizeof(fatal),
                     "FATAL policy-network-restore errno=%d selinux=%c "
                     "source=%s\n",
                     restore_errno, read_selinux(), selinux_policy_path());
    write_all(client, fatal, (size_t)n);
    return 0;
  }
  bootstrap_timeout.tv_sec = 70;
  (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &bootstrap_timeout,
                   sizeof(bootstrap_timeout));

  char hello[192];
  int hello_len = snprintf(hello, sizeof(hello),
                           "SESSION uid=%u broker_uid=%u pid=%d selinux=1 "
                           "policycaps=11100100 netlink=restored\n",
                           allowed_uid, geteuid(), getpid());
  if (write_all(client, hello, (size_t)hello_len) != 0) return 0;
  char *bootstrap_reply = calloc(1, MAX_RESPONSE);
  if (!bootstrap_reply) return 0;
  size_t bootstrap_used = (size_t)snprintf(
      bootstrap_reply, MAX_RESPONSE,
      "HANDOFF_RC=%d\nBOOTSTRAP_RESTORE=ok policycaps=11100100\n"
      "HANDOFF_STATUS_BEGIN\n",
      handoff_rc);
  if (status_path && bootstrap_used + 1 < MAX_RESPONSE) {
    bootstrap_used += read_bootstrap_status(
        status_path, bootstrap_reply + bootstrap_used,
        MAX_RESPONSE - bootstrap_used);
  }
  if (bootstrap_used + 96 < MAX_RESPONSE) {
    int ready = handoff_rc == 0 &&
                (strstr(bootstrap_reply, "state=READY") ||
                 strstr(bootstrap_reply, "state=MODULE_LOADED"));
    bootstrap_used += (size_t)snprintf(
        bootstrap_reply + bootstrap_used, MAX_RESPONSE - bootstrap_used,
        "\nHANDOFF_STATUS_END\nHANDOFF_READY=%d\n", ready);
  }
  write_all(client, bootstrap_reply, bootstrap_used);
  free(bootstrap_reply);
  if (write_response_end(client) != 0) return 0;

  while (running) {
    char request[MAX_REQUEST];
    size_t used = 0;
    while (used + 1 < sizeof(request)) {
      ssize_t n = read(client, request + used, sizeof(request) - used - 1);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) return 0;
      used += (size_t)n;
      if (memchr(request, '\n', used)) break;
    }
    request[used] = '\0';
    char *eol = strpbrk(request, "\r\n");
    if (eol) *eol = '\0';

    if (strcmp(request, "PING") == 0) {
      static const char pong[] = "PONG\n";
      write_all(client, pong, sizeof(pong) - 1);
    } else if (strcmp(request, "ID") == 0) {
      char reply[256];
      int n = snprintf(reply, sizeof(reply),
                       "uid=%u euid=%u gid=%u egid=%u pid=%d selinux=%c\n",
                       getuid(), geteuid(), getgid(), getegid(), getpid(),
                       read_selinux());
      write_all(client, reply, (size_t)n);
    } else if (strncmp(request, "EXEC ", 5) == 0 && request[5]) {
      char *reply = calloc(1, MAX_RESPONSE);
      if (!reply) {
        static const char oom[] = "ERROR no memory\n";
        write_all(client, oom, sizeof(oom) - 1);
      } else {
        size_t n = run_command(request + 5, reply, MAX_RESPONSE);
        write_all(client, reply, n);
        free(reply);
      }
    } else if (strncmp(request, "FS_LIST ", 8) == 0 && request[8]) {
      char *reply = calloc(1, MAX_RESPONSE);
      if (!reply) {
        static const char oom[] = "ERROR no memory\n";
        write_all(client, oom, sizeof(oom) - 1);
      } else {
        size_t n = fs_list(request + 8, reply, MAX_RESPONSE);
        write_all(client, reply, n);
        free(reply);
      }
    } else if (strncmp(request, "FS_STAT ", 8) == 0 && request[8]) {
      char *reply = calloc(1, MAX_RESPONSE);
      if (!reply) {
        static const char oom[] = "ERROR no memory\n";
        write_all(client, oom, sizeof(oom) - 1);
      } else {
        size_t n = fs_stat(request + 8, reply, MAX_RESPONSE);
        write_all(client, reply, n);
        free(reply);
      }
    } else if (strncmp(request, "FS_READ ", 8) == 0 && request[8]) {
      char *reply = calloc(1, MAX_RESPONSE);
      if (!reply) {
        static const char oom[] = "ERROR no memory\n";
        write_all(client, oom, sizeof(oom) - 1);
      } else {
        size_t n = fs_read(request + 8, reply, MAX_RESPONSE);
        write_all(client, reply, n);
        free(reply);
      }
    } else if (strcmp(request, "STOP") == 0) {
      static const char stopped[] = "STOPPING\n";
      write_all(client, stopped, sizeof(stopped) - 1);
      write_response_end(client);
      running = 0;
      break;
    } else {
      static const char help[] =
          "ERROR commands: PING, ID, EXEC <cmd>, FS_LIST <hex>, "
          "FS_STAT <hex>, FS_READ <hex>, STOP\n";
      write_all(client, help, sizeof(help) - 1);
    }
    if (write_response_end(client) != 0) break;
  }
  return 0;
}

static int daemonize_detached(void) {
  pid_t child = fork();
  if (child < 0) return -1;
  if (child > 0) return 1;
  if (setsid() < 0) _exit(111);

  int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  int logfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (nullfd >= 0) dup2(nullfd, STDIN_FILENO);
  if (logfd >= 0) {
    dup2(logfd, STDOUT_FILENO);
    dup2(logfd, STDERR_FILENO);
  }
  if (nullfd > STDERR_FILENO) close(nullfd);
  if (logfd > STDERR_FILENO) close(logfd);
  return 0;
}

/* GhostLock has already created a dedicated, single-threaded child before
 * execve().  Forking that task again makes the production kernel duplicate
 * the temporary credential a second time and is both redundant and risky.
 * Detach the existing child in place instead. */
static int detach_direct_child(void) {
  if (setsid() < 0 && errno != EPERM) return -1;
  int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  int logfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (nullfd < 0 || logfd < 0) {
    if (nullfd >= 0) close(nullfd);
    if (logfd >= 0) close(logfd);
    return -1;
  }
  if (dup2(nullfd, STDIN_FILENO) < 0 ||
      dup2(logfd, STDOUT_FILENO) < 0 ||
      dup2(logfd, STDERR_FILENO) < 0) {
    close(nullfd);
    close(logfd);
    return -1;
  }
  if (nullfd > STDERR_FILENO) close(nullfd);
  if (logfd > STDERR_FILENO) close(logfd);
  return 0;
}

int main(int argc, char **argv) {
  const char *abstract_name = DEFAULT_ABSTRACT;
  uid_t allowed_uid = (uid_t)-1;
  int daemon_mode = 0;
  int direct_child_mode = 0;
  int arm_timeout_ms = 15000;
  int reboot_after_ms = 0;
  pid_t holder_pid = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--daemon") == 0) {
      daemon_mode = 1;
    } else if (strcmp(argv[i], "--direct-child") == 0) {
      direct_child_mode = 1;
    } else if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || *end || v > UINT32_MAX) return 2;
      allowed_uid = (uid_t)v;
    } else if (strcmp(argv[i], "--abstract") == 0 && i + 1 < argc) {
      abstract_name = argv[++i];
    } else if (strcmp(argv[i], "--arm-timeout-ms") == 0 && i + 1 < argc) {
      char *end = NULL;
      long v = strtol(argv[++i], &end, 10);
      if (!end || *end || v < 1000 || v > 60000) return 2;
      arm_timeout_ms = (int)v;
    } else if (strcmp(argv[i], "--holder-pid") == 0 && i + 1 < argc) {
      char *end = NULL;
      long v = strtol(argv[++i], &end, 10);
      if (!end || *end || v <= 1 || v > INT32_MAX) return 2;
      holder_pid = (pid_t)v;
    } else if (strcmp(argv[i], "--reboot-after-ms") == 0 &&
               i + 1 < argc) {
      char *end = NULL;
      long v = strtol(argv[++i], &end, 10);
      if (!end || *end || v < 5000 || v > 300000) return 2;
      reboot_after_ms = (int)v;
    } else {
      fprintf(stderr, "usage: %s --uid UID [--daemon|--direct-child] "
                      "[--abstract NAME] "
                      "[--arm-timeout-ms MS] [--holder-pid PID] "
                      "[--reboot-after-ms MS]\n", argv[0]);
      return 2;
    }
  }
  if (allowed_uid == (uid_t)-1
#ifndef TCL_BROKER_TESTING
      || geteuid() != 0
#endif
  ) {
    fprintf(stderr, "broker requires euid=0 and --uid\n");
    return 3;
  }
  size_t abstract_len = strlen(abstract_name);
  if (!abstract_len || abstract_len + 1 >=
                           sizeof(((struct sockaddr_un *)0)->sun_path))
    return 4;

  umask(077);
  if (daemon_mode && direct_child_mode) return 5;
  if (holder_pid > 1 &&
      (!direct_child_mode || getppid() != holder_pid)) return 5;
  if (direct_child_mode) {
    if (detach_direct_child() != 0) return 5;
  } else if (daemon_mode) {
    int d = daemonize_detached();
    if (d < 0) return 5;
    if (d > 0) return 0;
  }

  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, stop_handler);
  signal(SIGINT, stop_handler);

  int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server < 0) return 6;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  memcpy(addr.sun_path + 1, abstract_name, abstract_len);
  socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                  1 + abstract_len);
  if (bind(server, (struct sockaddr *)&addr, addr_len) != 0 ||
      listen(server, 4) != 0) {
    close(server);
    return 7;
  }
  dprintf(STDOUT_FILENO, "broker pid=%d allowed_uid=%u abstract=%s\n",
          getpid(), allowed_uid, abstract_name);

  long arm_deadline = monotonic_ms() + arm_timeout_ms;
  int authorized_session = 0;
  while (running && !authorized_session) {
    long remain = arm_deadline - monotonic_ms();
    if (remain <= 0) break;
    struct pollfd p = {.fd = server, .events = POLLIN};
    int pr = poll(&p, 1, remain > 250 ? 250 : (int)remain);
    if (pr < 0 && errno == EINTR) continue;
    if (pr <= 0) continue;
    int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0) continue;
    int rejected = serve_client(client, allowed_uid);
    close(client);
    if (!rejected) authorized_session = 1;
  }

  close(server);
  /* Timeout, signal and normal disconnect all close the permissive window.
   *
   * Do not signal the raw W2 holder here.  kill()+immediate broker exit has
   * no completion handshake: the broker can close its inherited io_uring
   * descriptors before the holder has finished exit_creds(), releasing the
   * page that still backs the temporary credential.  The TCL target has
   * repeatedly lost networking immediately after that race.  The holder is
   * deliberately parked and keeps its private descriptor table pinned; a
   * full reboot is the only supported cleanup boundary for this volatile
   * session. */
  int enforce_rc = close_permissive_window();
  int enforce_errno = enforce_rc == 0 ? 0 : errno;
  if (enforce_rc != 0 && reboot_after_ms > 0) {
    /* A failed policy/network or enforcing restoration must not leave the TV
     * in an incoherent state.  Give marker I/O one second, then reboot. */
    errno = enforce_errno;
    watchdog_reboot_or_park(1000, enforce_rc);
  }
  if (enforce_rc != 0) return 9;
  if (park_after_success() != 0) return 10;
  return 0;
}
