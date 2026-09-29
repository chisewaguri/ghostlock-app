API ?= 35

# Auto-detect NDK
ifeq ($(OS),Windows_NT)
  PREBUILT := windows-x86_64
  CLANG := aarch64-linux-android$(API)-clang.cmd
  NDK_DIRS := $(subst \,/,$(wildcard \
    $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/* \
    $(subst \,/,$(ANDROID_HOME))/ndk/* \
    D:/AndroidSDK/ndk/*))
  # newest NDK that actually ships the compiler; a half-installed dir (ndk/27.1
  # here has no toolchains/llvm/prebuilt) is skipped rather than picked
  NDK_ROOT ?= $(lastword $(foreach d,$(NDK_DIRS),$(if $(wildcard $(d)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANG)),$(d))))
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANG)
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
  PREBUILT := linux-x86_64
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang
endif

SRCS := \
  src/core/main.c \
  src/core/offsets_json.c \
  src/core/util.c \
  src/core/fops.c

# Headers also trigger a rebuild (e.g. a freshly --register-ed src/kernels/<release>/offsets.h).
HDRS := $(wildcard src/core/*.h src/core/*/*.h src/kernels/*.h src/kernels/*/*.h)

# Device offsets are selected at runtime from uname -r.
TARGET_CONFIG ?= target.h

CFLAGS = -O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"$(TARGET_CONFIG)\"
LDFLAGS := -fPIE -pie -pthread -flto

.PHONY: all clean product route-geom-check

all: ghostlock

# Host-side check of the route geometry predicates (no NDK, no device).
CC_HOST ?= cc
route-geom-check:
	$(CC_HOST) -Isrc -Isrc/core -Isrc/kernels -Wall -o route_geom_check test/route_geom_check.c
	./route_geom_check

ghostlock: $(SRCS) $(HDRS)
	@if [ -z "$(NDK_ROOT)" ]; then \
	  echo "no NDK found (looked in $(NDK_DIRS)); set NDK_ROOT"; exit 1; \
	fi
	@echo "Using NDK compiler: $(NDK_CC)"
	@echo "Target config: $(TARGET_CONFIG)"
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o ghostlock

product: ghostlock
	@echo "=== ghostlock binary ready: ./ghostlock ==="
	@echo "构建 APK: .\gradlew.bat :app:assembleDebug"

clean:
	rm -f ghostlock route_geom_check
