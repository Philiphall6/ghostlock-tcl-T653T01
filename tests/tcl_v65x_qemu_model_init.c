#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef GL_QEMU_ROOT_TASK_GROUP
#define GL_QEMU_ROOT_TASK_GROUP "0"
#endif

static void make_dir(const char *path) {
  if (mkdir(path, 0755) != 0 && errno != EEXIST) {
    dprintf(1, "GLV65XMODEL FAIL mkdir %s errno=%d\n", path, errno);
    _exit(1);
  }
}

int main(void) {
  struct rlimit files = {.rlim_cur = 4096, .rlim_max = 4096};
  setvbuf(stdout, NULL, _IONBF, 0);
  make_dir("/dev");
  make_dir("/proc");
  make_dir("/sys");
  make_dir("/data");
  make_dir("/data/local");
  make_dir("/data/local/tmp");
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0 ||
      mount("proc", "/proc", "proc", 0, NULL) != 0 ||
      mount("sysfs", "/sys", "sysfs", 0, NULL) != 0) {
    dprintf(1, "GLV65XMODEL FAIL mount errno=%d\n", errno);
    return 1;
  }
  setrlimit(RLIMIT_NOFILE, &files);
  setenv("TCL_MCAST_HELPER", "/tcl-v65x-newselect-helper", 1);
  setenv("TCL_V65X_QEMU_MODEL_RELEASE", "5.15.192-android14-11", 1);
  setenv("FOPS_MAX_ATTEMPTS", "1", 1);
  setenv("KSNITCH_VERBOSE", "0", 1);
  setenv("TCL_QEMU_OBSERVER_DIAG", "0", 1);
  setenv("TCL_QEMU_ROOT_TASK_GROUP", GL_QEMU_ROOT_TASK_GROUP, 1);

  pid_t child = fork();
  if (child == 0) {
    if (setresgid(1000, 1000, 1000) != 0 ||
        setresuid(1000, 1000, 1000) != 0 ||
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
      dprintf(1, "GLV65XMODEL FAIL drop uid errno=%d\n", errno);
      _exit(1);
    }
    execl("/ghostlock-tcl-v65x-qemu-model",
          "ghostlock-tcl-v65x-qemu-model", "--selftest", NULL);
    dprintf(1, "GLV65XMODEL FAIL exec errno=%d\n", errno);
    _exit(127);
  }
  int status = 0;
  waitpid(child, &status, 0);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    dprintf(1, "GLV65XMODEL PASS: shared reclaim + ARM32 _newselect + "
               "rb_erase schema completed in the surrogate kernel\n");
  else
    dprintf(1, "GLV65XMODEL FAIL child_status=%d\n", status);
  sync();
  reboot(RB_POWER_OFF);
  return 0;
}
