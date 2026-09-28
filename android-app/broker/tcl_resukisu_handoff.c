#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef EXPECTED_RELEASE
#define EXPECTED_RELEASE "5.15.180-android14-11"
#endif
#define MAX_SELINUX_POLICY (16U * 1024U * 1024U)
#ifndef EXPECTED_SELINUX_POLICY_SIZE
#define EXPECTED_SELINUX_POLICY_SIZE 1030054U
#endif
#ifndef EXPECTED_SELINUX_POLICY_SIZE_ALT
#define EXPECTED_SELINUX_POLICY_SIZE_ALT EXPECTED_SELINUX_POLICY_SIZE
#endif
#define REQUIRED_MANAGER_PACKAGE "com.philiphall6.resukisu.tcl"
#ifndef TCL_LAB_PREFIX
#define TCL_LAB_PREFIX "/data/local/tmp/tcl-v643-resukisu-lab/"
#endif

static int read_first(const char *path);

static const char *enforce_path(void) {
#ifdef TCL_HANDOFF_TESTING
  const char *value = getenv("TCL_HANDOFF_ENFORCE_FILE");
  if (value && value[0]) return value;
#endif
  return "/sys/fs/selinux/enforce";
}

static const char *modules_path(void) {
#ifdef TCL_HANDOFF_TESTING
  const char *value = getenv("TCL_HANDOFF_MODULES_FILE");
  if (value && value[0]) return value;
#endif
  return "/proc/modules";
}

static const char *policy_path(void) {
#ifdef TCL_HANDOFF_TESTING
  const char *value = getenv("TCL_HANDOFF_POLICY_FILE");
  if (value && value[0]) return value;
#endif
  /* The live policy export on TCL 5.15 omits both Android netlink config
   * bits.  Reloading that serialization can break Ethernet and Wi-Fi.  Use
   * only the exact, verified combined policy from the read-only vendor
   * partition. */
  return "/vendor/etc/selinux/precompiled_sepolicy";
}

static const char *policy_load_path(void) {
#ifdef TCL_HANDOFF_TESTING
  const char *value = getenv("TCL_HANDOFF_LOAD_FILE");
  if (value && value[0]) return value;
#endif
  return "/sys/fs/selinux/load";
}

static const char *policycap_dir(void) {
#ifdef TCL_HANDOFF_TESTING
  const char *value = getenv("TCL_HANDOFF_POLICYCAP_DIR");
  if (value && value[0]) return value;
  return NULL;
#else
  return "/sys/fs/selinux/policy_capabilities";
#endif
}

static uint32_t load_le32(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int verify_tcl_policy_header(const unsigned char *policy,
                                    size_t size) {
  const uint32_t policy_magic = 0xf97cff8cU;
  const uint32_t policy_version = 30U;
  const uint32_t policy_config = 0xc0000001U;
  static const unsigned char target[] = "SE Linux";
  if ((size != EXPECTED_SELINUX_POLICY_SIZE &&
       size != EXPECTED_SELINUX_POLICY_SIZE_ALT) ||
      load_le32(policy) != policy_magic) {
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
  if (version != policy_version || config != policy_config) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int verify_tcl_policycaps(void) {
  static const struct {
    const char *name;
    char expected;
  } caps[] = {
      {"network_peer_controls", '1'},
      {"open_perms", '1'},
      {"extended_socket_class", '1'},
      {"always_check_network", '0'},
      {"cgroup_seclabel", '0'},
      {"nnp_nosuid_transition", '1'},
      {"genfs_seclabel_symlinks", '0'},
      {"ioctl_skip_cloexec", '0'},
  };
  const char *dir = policycap_dir();
  if (!dir) return 0;
  for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, caps[i].name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
      errno = ENAMETOOLONG;
      return -1;
    }
    if (read_first(path) != caps[i].expected) {
      errno = EPROTO;
      return -1;
    }
  }
  return 0;
}

/* Restore the SELinux network semantics damaged by the temporary rb_erase
 * pointer before either the handoff or the module may enable enforcement.
 * Reloading the exact vendor policy repopulates policycap[0..7] and both
 * Android netlink flags through security_load_policycaps(). */
static int restore_network_policy_state(void) {
  int source = open(policy_path(), O_RDONLY | O_CLOEXEC);
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
  if (verify_tcl_policy_header(policy, used) != 0) {
    free(policy);
    return -1;
  }

  int flags = O_WRONLY | O_CLOEXEC;
#ifdef TCL_HANDOFF_TESTING
  flags |= O_TRUNC;
#endif
  int load = open(policy_load_path(), flags);
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
  return verify_tcl_policycaps();
}

static long monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return now.tv_sec * 1000L + now.tv_nsec / 1000000L;
}

static int read_first(const char *path) {
  char value = '?';
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return value;
  if (read(fd, &value, 1) != 1) value = '?';
  close(fd);
  return value;
}

static int safe_path(const char *path, int status_path) {
  if (!path || path[0] != '/' || strlen(path) >= PATH_MAX - 64) return 0;
#ifdef TCL_HANDOFF_TESTING
  (void)status_path;
  return 1;
#else
  if (strstr(path, "/../") || strstr(path, "/./")) return 0;
  if (status_path) return strncmp(path, "/data/local/tmp/", 16) == 0;
  if (strncmp(path, "/data/app/", 10) == 0) return 1;
  return strncmp(path, TCL_LAB_PREFIX, sizeof(TCL_LAB_PREFIX) - 1) == 0;
#endif
}

static int valid_package_name(const char *name) {
  if (!name || !name[0] || strlen(name) >= 192 || !strchr(name, '.'))
    return 0;
  for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') || *p == '.' || *p == '_')
      continue;
    return 0;
  }
  return 1;
}

static int write_status(const char *path, const char *format, ...) {
  char body[2048];
  va_list arguments;
  va_start(arguments, format);
  int count = vsnprintf(body, sizeof(body), format, arguments);
  va_end(arguments);
  if (count < 0 || (size_t)count >= sizeof(body)) return -1;

  char temporary[PATH_MAX];
  int n = snprintf(temporary, sizeof(temporary), "%s.%d.tmp", path,
                   (int)getpid());
  if (n < 0 || (size_t)n >= sizeof(temporary)) return -1;
  int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) return -1;
  size_t offset = 0;
  while (offset < (size_t)count) {
    ssize_t written = write(fd, body + offset, (size_t)count - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) {
      close(fd);
      unlink(temporary);
      return -1;
    }
    offset += (size_t)written;
  }
  (void)fsync(fd);
  close(fd);
  if (chmod(temporary, 0644) != 0 || rename(temporary, path) != 0) {
    unlink(temporary);
    return -1;
  }
  return 0;
}

static int wait_bounded(pid_t child, int timeout_ms) {
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
      (void)kill(child, SIGKILL);
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) { }
      return 124;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    (void)nanosleep(&pause, NULL);
  }
}

static int module_loaded(void);
static int ksu_available(const char *ksud);

enum kernel_witness {
  WITNESS_NONE = 0,
  WITNESS_PROC_MODULES = 1,
  WITNESS_SUPERCALL = 2,
};

static enum kernel_witness kernel_witness(const char *ksud) {
  if (module_loaded()) return WITNESS_PROC_MODULES;
  if (ksu_available(ksud)) return WITNESS_SUPERCALL;
  return WITNESS_NONE;
}

static const char *witness_name(enum kernel_witness witness) {
  if (witness == WITNESS_PROC_MODULES) return "proc_modules";
  if (witness == WITNESS_SUPERCALL) return "supercall";
  return "none";
}

static int run_bounded(const char *path, char *const argv[], int timeout_ms) {
  pid_t child = fork();
  if (child < 0) return 126;
  if (child == 0) {
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    execv(path, argv);
    _exit(127);
  }
  return wait_bounded(child, timeout_ms);
}

/* The custom TCL ksud command loads the exact module and then enters
 * late-load without a second exec.  Loading the module re-enables SELinux;
 * therefore killing this child at the first /proc/modules witness would
 * discard the only process that owns the new KernelSU credentials/domain. */
static int run_until_module_loaded(const char *path, char *const argv[],
                                   const char *status_path, int timeout_ms,
                                   enum kernel_witness *final_witness) {
  pid_t child = fork();
  if (child < 0) return 126;
  if (child == 0) {
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    execv(path, argv);
    _exit(127);
  }

  long deadline = monotonic_ms() + timeout_ms;
  long next_supercall_probe = 0;
  long next_progress = monotonic_ms() + 250;
  int progress_step = 0;
  enum kernel_witness witness = WITNESS_NONE;
  int status = 0;
  for (;;) {
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) {
      witness = kernel_witness(path);
      if (witness != WITNESS_NONE) {
        if (final_witness) *final_witness = witness;
        return 0;
      }
      if (WIFEXITED(status)) return WEXITSTATUS(status);
      if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
      return 125;
    }
    if (waited < 0 && errno != EINTR) return 126;

    long now = monotonic_ms();
    witness = module_loaded() ? WITNESS_PROC_MODULES : WITNESS_NONE;
    if (witness == WITNESS_NONE && now >= next_supercall_probe) {
      if (ksu_available(path)) witness = WITNESS_SUPERCALL;
      next_supercall_probe = now + 250;
    }
    if (witness != WITNESS_NONE) {
      if (final_witness) *final_witness = witness;
    }
    if (now >= next_progress && progress_step < 4) {
      static const int milestones[] = {250, 1000, 5000, 15000};
      (void)write_status(status_path,
                         "state=INSMOD_RUNNING\nelapsed_ms=%d\n"
                         "witness=%s\nselinux=%c\n",
                         milestones[progress_step], witness_name(witness),
                         read_first(enforce_path()));
      progress_step++;
      next_progress = monotonic_ms() +
                      (progress_step < 4
                           ? milestones[progress_step] -
                                 milestones[progress_step - 1]
                           : timeout_ms);
    }
    if (now >= deadline) {
      (void)kill(child, SIGKILL);
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) { }
      witness = kernel_witness(path);
      if (final_witness) *final_witness = witness;
      return 124;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    (void)nanosleep(&pause, NULL);
  }
}

static int module_loaded(void) {
#ifdef TCL_HANDOFF_TESTING
  static int checks;
  const char *appears = getenv("TCL_HANDOFF_TEST_MODULE_APPEARS");
  if (appears && strcmp(appears, "1") == 0) return checks++ > 0;
#endif
  FILE *stream = fopen(modules_path(), "re");
  if (!stream) return 0;
  char line[1024];
  int found = 0;
  while (fgets(line, sizeof(line), stream)) {
    if (strncmp(line, "kernelsu ", 9) == 0) {
      found = 1;
      break;
    }
  }
  fclose(stream);
  return found;
}

/*
 * ReSukiSU's jailbreak loader can install its LKM without registering a
 * conventional entry in /proc/modules.  The manager then sees an active LKM
 * while a /proc/modules-only handoff waits forever.  Probe the same KernelSU
 * supercall used by userspace and accept only a strictly positive version.
 */
static int ksu_available(const char *ksud) {
#ifdef TCL_HANDOFF_TESTING
  (void)ksud;
  return module_loaded();
#else
  int output_pipe[2];
  if (pipe2(output_pipe, O_CLOEXEC) != 0) return 0;
  pid_t child = fork();
  if (child < 0) {
    close(output_pipe[0]);
    close(output_pipe[1]);
    return 0;
  }
  if (child == 0) {
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    close(output_pipe[0]);
    if (dup2(output_pipe[1], STDOUT_FILENO) < 0) _exit(127);
    close(output_pipe[1]);
    char *const probe_argv[] = {(char *)ksud, "debug", "version", NULL};
    execv(ksud, probe_argv);
    _exit(127);
  }

  close(output_pipe[1]);
  int result = wait_bounded(child, 2000);
  char output[256];
  size_t used = 0;
  while (used + 1 < sizeof(output)) {
    ssize_t count = read(output_pipe[0], output + used,
                         sizeof(output) - used - 1);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) break;
    used += (size_t)count;
  }
  close(output_pipe[0]);
  output[used] = '\0';
  if (result != 0) return 0;
  const char prefix[] = "Kernel Version:";
  char *marker = strstr(output, prefix);
  if (!marker) return 0;
  marker += sizeof(prefix) - 1;
  errno = 0;
  char *end = NULL;
  long version = strtol(marker, &end, 10);
  return errno == 0 && end != marker && version > 0;
#endif
}

static int restore_worker(void) {
  if (read_first(enforce_path()) == '1') return 0;
  int fd = open(enforce_path(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) return 1;
  ssize_t written = write(fd, "1", 1);
  close(fd);
  if (written != 1) return 2;
  for (int attempt = 0; attempt < 200; attempt++) {
    if (read_first(enforce_path()) == '1') return 0;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    (void)nanosleep(&pause, NULL);
  }
  return 3;
}

/* Run the potentially blocking SELinux sysfs transition in a disposable
 * child.  The one-shot handoff itself never waits indefinitely. */
static int restore_enforcing_bounded(void) {
  if (read_first(enforce_path()) == '1')
    return verify_tcl_policycaps() == 0 ? 0 : 5;
  pid_t child = fork();
  if (child < 0) return 126;
  if (child == 0) _exit(restore_worker());
  int result = wait_bounded(child, 5000);
  if (result != 0) return result;
  if (read_first(enforce_path()) != '1') return 4;
  return verify_tcl_policycaps() == 0 ? 0 : 5;
}

static void detach_stdio(void) {
  (void)setsid();
  int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
  int output = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (input >= 0) {
    (void)dup2(input, STDIN_FILENO);
    if (input > STDERR_FILENO) close(input);
  }
  if (output >= 0) {
    (void)dup2(output, STDOUT_FILENO);
    (void)dup2(output, STDERR_FILENO);
    if (output > STDERR_FILENO) close(output);
  }
}

int main(int argc, char **argv) {
  const char *preflight = NULL;
  const char *ksud = NULL;
  const char *module = NULL;
  const char *status = NULL;
  const char *manager_package = getenv("TCL_RESUKISU_MANAGER_PACKAGE");
  if (!manager_package || !manager_package[0])
    manager_package = REQUIRED_MANAGER_PACKAGE;
  int completion_fd = -1;
  int direct_child = 0;
  for (int index = 1; index < argc; index++) {
    if (strcmp(argv[index], "--direct-child") == 0) {
      direct_child = 1;
    } else if (strcmp(argv[index], "--preflight") == 0 && index + 1 < argc) {
      preflight = argv[++index];
    } else if (strcmp(argv[index], "--ksud") == 0 && index + 1 < argc) {
      ksud = argv[++index];
    } else if (strcmp(argv[index], "--module") == 0 && index + 1 < argc) {
      module = argv[++index];
    } else if (strcmp(argv[index], "--status") == 0 && index + 1 < argc) {
      status = argv[++index];
    } else if (strcmp(argv[index], "--completion-fd") == 0 &&
               index + 1 < argc) {
      char *end = NULL;
      long value = strtol(argv[++index], &end, 10);
      if (!end || *end || value < 3 || value > INT_MAX) return 2;
      completion_fd = (int)value;
    } else if (strcmp(argv[index], "--package-name") == 0 &&
               index + 1 < argc) {
      manager_package = argv[++index];
    } else {
      return 2;
    }
  }

  int privileged = getuid() == 0 && geteuid() == 0;
#ifdef TCL_HANDOFF_TESTING
  privileged = 1;
#endif
  if (!direct_child || !privileged ||
      !safe_path(preflight, 0) || !safe_path(ksud, 0) ||
      !safe_path(module, 0) || !safe_path(status, 1) ||
      access(preflight, X_OK) != 0 || access(ksud, X_OK) != 0 ||
      access(module, R_OK) != 0 || completion_fd < 0 ||
      fcntl(completion_fd, F_GETFD) < 0 ||
      !valid_package_name(manager_package) ||
      strcmp(manager_package, REQUIRED_MANAGER_PACKAGE) != 0) {
    return 3;
  }
  if (fcntl(completion_fd, F_SETFD, FD_CLOEXEC) != 0) return 3;

#ifndef TCL_HANDOFF_TESTING
  struct utsname kernel;
  memset(&kernel, 0, sizeof(kernel));
  if (uname(&kernel) != 0 || strcmp(kernel.release, EXPECTED_RELEASE) != 0)
    return 4;
#endif

  detach_stdio();
  (void)write_status(status,
                     "state=STARTED\npid=%d\nuid=%u\nselinux=%c\n",
                     (int)getpid(), (unsigned)geteuid(),
                     read_first(enforce_path()));

  if (read_first(enforce_path()) != '0') {
    (void)write_status(status, "state=REFUSED\nreason=selinux-window\n");
    return 5;
  }
  errno = 0;
  if (restore_network_policy_state() != 0) {
    int saved = errno;
    (void)write_status(status,
                       "state=FAILED\nphase=policy-network-restore\n"
                       "errno=%d\nselinux=%c\n",
                       saved, read_first(enforce_path()));
    return 7;
  }
  (void)write_status(status,
                     "state=POLICY_NETWORK_RESTORED\n"
                     "policycaps=11100100\nandroid_netlink=route,getneigh\n"
                     "selinux=%c\n",
                     read_first(enforce_path()));
  enum kernel_witness existing = kernel_witness(ksud);
  if (existing != WITNESS_NONE) {
    int enforcing = restore_enforcing_bounded();
    (void)write_status(status,
                       "state=REFUSED\nreason=module-already-loaded\n"
                       "witness=%s\nrestore_rc=%d\nselinux=%c\n",
                       witness_name(existing), enforcing,
                       read_first(enforce_path()));
    return 6;
  }

  (void)write_status(status,
                     "state=PREFLIGHT_START\nuid=%u\nselinux=%c\n",
                     (unsigned)geteuid(), read_first(enforce_path()));
  char *const preflight_argv[] = {(char *)preflight, NULL};
  int preflight_rc = run_bounded(preflight, preflight_argv, 30000);
  if (preflight_rc != 0) {
    int enforcing = restore_enforcing_bounded();
    (void)write_status(status,
                       "state=FAILED\nphase=preflight\nrc=%d\n"
                       "restore_rc=%d\nselinux=%c\n",
                       preflight_rc, enforcing, read_first(enforce_path()));
    return 10;
  }
  (void)write_status(status,
                     "state=PREFLIGHT_OK\nuid=%u\nselinux=%c\n",
                     (unsigned)geteuid(), read_first(enforce_path()));

  char *const ksud_argv[] = {
      (char *)ksud, "tcl-late-load", (char *)module,
      "--status", (char *)status,
      "--package-name", (char *)manager_package, NULL};
  (void)write_status(status,
                     "state=TCL_CHAIN_START\nuid=%u\nselinux=%c\n",
                     (unsigned)geteuid(), read_first(enforce_path()));
  enum kernel_witness loaded = WITNESS_NONE;
  int load_rc = run_until_module_loaded(ksud, ksud_argv, status, 45000,
                                        &loaded);
  if (loaded == WITNESS_NONE) loaded = kernel_witness(ksud);
  if (load_rc != 0 || loaded == WITNESS_NONE) {
    int enforcing = restore_enforcing_bounded();
    (void)write_status(status,
                       "state=FAILED\nphase=load\nrc=%d\nwitness=%s\n"
                       "restore_rc=%d\nselinux=%c\n",
                       load_rc, witness_name(loaded), enforcing,
                       read_first(enforce_path()));
    return 11;
  }

  int enforcing = restore_enforcing_bounded();
  int final_state = read_first(enforce_path());
  if (enforcing != 0 || final_state != '1') {
    (void)write_status(status,
                       "state=FAILED\nphase=restore-enforcing\n"
                       "restore_rc=%d\nmodule=kernelsu\nselinux=%c\n",
                       enforcing, final_state);
    return 12;
  }

  /* The detached ksud process is authoritative for READY/FAILED.  Do not
   * overwrite its durable phase journal here; it may still be completing
   * userspace installation when this parent returns. */
  return 0;
}
