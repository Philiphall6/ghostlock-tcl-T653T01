API ?= 35

NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang
NDK_ARM32_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi$(API)-clang

SRCS := \
  src/core/main.c \
  src/core/util.c \
  src/core/fops.c

CFLAGS := -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\" \
  -include stubs/dl_stub.h
LDFLAGS := -static -pthread

.PHONY: all clean ghostlock-tcl-v643-lab profile-guard-test tcl-v643-stack-geometry-test \
	tcl-v643-syscall-stack-model-test \
	tcl-v643-pi-blocked-on-model-test \
	tcl-v643-pselect-rounds-model-test \
	tcl-v643-pselect-semantics-test tcl-v643-runtime-offsets-test \
	tcl-v643-slub-reclaim-model-test tcl-v643-io-uring-pcp-model-test \
	tcl-v643-compat-select-model-test tcl-v643-direct-primitive-model-test \
	tcl-v643-kaslr-model-test tcl-v643-mcast-geometry-test \
	tcl-v643-mcast-carrier-test tcl-v643-mcast-helper \
	tcl-v643-cleanup-invariants-test tcl-v643-capture-witness-test \
	tcl-v643-uring-perf-witness-test tcl-v643-sid-probe-model-test \
	tcl-v643-uring-perf-probe

all: ghostlock

ghostlock: $(SRCS)
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# Explicitly armed laboratory build.  The ordinary `ghostlock` target keeps
# the profile's analysis_only stop.  This target exists for the disposable
# uninstrumented QEMU gate and must not be copied to the TV by automation.
ghostlock-tcl-v643-lab: $(SRCS)
	$(NDK_CC) $(CFLAGS) -DTCL_V643_LAB_ARMING=1 $(LDFLAGS) $^ -o $@

clean:
	rm -f ghostlock ghostlock-tcl-v643-lab tcl-v643-mcast-helper \
		tcl-v643-uring-perf-probe

# Android/device-side non-arming feasibility probe for a PFN-free capture
# witness. It uses ordinary io_uring, poll and perf sampling only.
tcl-v643-uring-perf-probe: tests/tcl_v643_uring_perf_probe.c
	$(NDK_CC) -O2 -Wall -static $< -o $@

# Non-arming AArch32 component used to freeze the split-ABI boundary.  It has
# no command that issues the carrier syscall; --selftest only checks ILP32,
# the fixed-width protocol and byte layout.
tcl-v643-mcast-helper: src/helpers/tcl_v643_mcast_helper.c
	$(NDK_ARM32_CC) $(CFLAGS) $(LDFLAGS) $< -o $@

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

# Host-only coordinate model for the exact V643 syscall entry, dormant
# random-kstack alternative, signal delivery, stale waiter and pselect frame.
# It performs no syscall and does not build the exploit implementation.
tcl-v643-syscall-stack-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_syscall_stack_model.c -o /tmp/tcl-v643-syscall-stack-model
	/tmp/tcl-v643-syscall-stack-model

# Host-only state model of the vulnerable V643 proxy-lock rollback.  It
# contains no futex syscall, timing choreography, reclaim or kernel address.
tcl-v643-pi-blocked-on-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_pi_blocked_on_model.c -o /tmp/tcl-v643-pi-blocked-on-model
	/tmp/tcl-v643-pi-blocked-on-model

# Host-only control-flow model for the TCL carrier's one-write-per-pselect
# retry loop. It issues no syscall and does not build the exploit.
tcl-v643-pselect-rounds-model-test:
	$(CC) -O2 -Wall tests/tcl_v643_pselect_rounds_model.c -o /tmp/tcl-v643-pselect-rounds-model
	/tmp/tcl-v643-pselect-rounds-model

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

# Host-only coordinate model for the ARM32 compat select route recovered from
# the exact V643 image.  It issues no syscall and does not build the exploit.
tcl-v643-compat-select-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_compat_select_model.c -o /tmp/tcl-v643-compat-select-model
	/tmp/tcl-v643-compat-select-model

# Host-only model of the exact V643 panic scratch, boot_id ctl_table data
# pointer and rb_erase collateral store.  It performs no syscall.
tcl-v643-direct-primitive-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_direct_primitive_model.c -o /tmp/tcl-v643-direct-primitive-model
	/tmp/tcl-v643-direct-primitive-model

# Host-only coordinate proof for the 2 MiB-aligned V643 image slide and
# first-block syscall entry text.  It opens no perf event.
tcl-v643-kaslr-model-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_kaslr_model.c -o /tmp/tcl-v643-kaslr-model
	/tmp/tcl-v643-kaslr-model

# Host-only coordinate proof for the native and AArch32-compat IPv4
# MCAST_BLOCK_SOURCE copies in the exact V643 image. It issues no syscall.
tcl-v643-mcast-geometry-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_mcast_geometry.c -o /tmp/tcl-v643-mcast-geometry
	/tmp/tcl-v643-mcast-geometry

# Host-only byte-layout validation for the ARM32 compat MCAST source request.
# It does not issue setsockopt, futex, reclaim or any other syscall.
tcl-v643-mcast-carrier-test:
	$(CC) -O2 -Wall -Isrc/devices tests/tcl_v643_mcast_carrier.c -o /tmp/tcl-v643-mcast-carrier
	/tmp/tcl-v643-mcast-carrier

# Host-only cleanup state model derived from the exact V643 rtmutex
# disassembly. It contains no futex syscall and cannot arm the vulnerability.
tcl-v643-cleanup-invariants-test:
	$(CC) -O2 -Wall tests/tcl_v643_cleanup_invariants.c -o /tmp/tcl-v643-cleanup-invariants
	/tmp/tcl-v643-cleanup-invariants

# Host-only parser/verdict tests for the pre-trigger PFN witness.  No futex,
# io_uring, reclaim, kernel address or device access is performed.
tcl-v643-capture-witness-test:
	$(CC) -O2 -Wall tests/tcl_v643_capture_witness.c -o /tmp/tcl-v643-capture-witness
	/tmp/tcl-v643-capture-witness

# Host-only exact-IP/register semantics for the PFN-free io_uring witness.
# It parses synthetic register states and issues no syscall.
tcl-v643-uring-perf-witness-test:
	$(CC) -O2 -Wall tests/tcl_v643_uring_perf_witness.c -o /tmp/tcl-v643-uring-perf-witness
	/tmp/tcl-v643-uring-perf-witness

# Host-only state model for the post-cred candidate-first SID probe.  It
# validates fail-closed selection and contains no syscall or device access.
tcl-v643-sid-probe-model-test:
	$(CC) -O2 -Wall tests/tcl_v643_sid_probe_model.c -o /tmp/tcl-v643-sid-probe-model
	/tmp/tcl-v643-sid-probe-model
