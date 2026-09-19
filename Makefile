API ?= 35

NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang

SRCS := \
  src/core/main.c \
  src/core/util.c \
  src/core/fops.c

CFLAGS := -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  -include stubs/dl_stub.h
LDFLAGS := -static -pthread

.PHONY: all clean profile-guard-test tcl-v643-stack-geometry-test \
	tcl-v643-pselect-semantics-test tcl-v643-runtime-offsets-test \
	tcl-v643-slub-reclaim-model-test tcl-v643-io-uring-pcp-model-test

all: ghostlock

ghostlock: $(SRCS)
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f ghostlock

# Native, host-only validation of the non-runnable TCL profile.  This target
# does not compile or execute the exploit implementation.
profile-guard-test:
	$(CC) -O2 -Wall -Isrc/devices tests/profile_guard.c -o /tmp/ghostlock-profile-guard
	/tmp/ghostlock-profile-guard

# Host-only static model of offsets recovered from the exact TCL V643 binary.
# It neither builds nor runs the exploit implementation.
tcl-v643-stack-geometry-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_stack_geometry.c -o /tmp/tcl-v643-stack-geometry
	/tmp/tcl-v643-stack-geometry

# Host-only Linux semantics check for the proposed exceptfds carrier.  No
# vulnerable futex operation or kernel address is used.
tcl-v643-pselect-semantics-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_pselect_semantics.c -o /tmp/tcl-v643-pselect-semantics
	/tmp/tcl-v643-pselect-semantics

# Host-only verification that the macros consumed by the implementation are
# actually overridden by the TCL profile rather than inherited from target.h.
tcl-v643-runtime-offsets-test:
	$(CC) -O2 -Wall -Isrc/core -Isrc/devices tests/tcl_v643_runtime_offsets.c -o /tmp/tcl-v643-runtime-offsets
	/tmp/tcl-v643-runtime-offsets

# Host-only state model of the exact V643 SLUB thresholds.  It proves the
# required batching bounds but does not allocate kernel objects or exercise
# the vulnerability.
tcl-v643-slub-reclaim-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_slub_reclaim_model.c -o /tmp/tcl-v643-slub-reclaim-model
	/tmp/tcl-v643-slub-reclaim-model

# Host-only state model of the exact V643 io_uring order/migratetype and PCP
# LIFO conditions.  It does not issue io_uring syscalls or touch the TV.
tcl-v643-io-uring-pcp-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_io_uring_pcp_model.c -o /tmp/tcl-v643-io-uring-pcp-model
	/tmp/tcl-v643-io-uring-pcp-model
