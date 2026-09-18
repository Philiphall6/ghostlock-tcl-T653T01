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

.PHONY: all clean profile-guard-test

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
