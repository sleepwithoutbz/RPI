CLANG ?= clang
ARCH ?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
TARGET_ARCH := arm64
else ifeq ($(ARCH),arm64)
TARGET_ARCH := arm64
else ifeq ($(ARCH),s390x)
TARGET_ARCH := s390
else ifeq ($(ARCH),ppc64le)
TARGET_ARCH := powerpc
else ifeq ($(ARCH),mips)
TARGET_ARCH := mips
else ifeq ($(ARCH),mips64)
TARGET_ARCH := mips
else ifeq ($(ARCH),riscv64)
TARGET_ARCH := riscv
else ifeq ($(ARCH),loongarch64)
TARGET_ARCH := loongarch
else
$(error Unsupported ARCH '$(ARCH)'; set ARCH=<uname -m> or TARGET_ARCH=<libbpf arch>)
endif

BPF_CFLAGS := \
    -O2 \
    -g \
    -target bpf \
    -D__TARGET_ARCH_$(TARGET_ARCH) \
    -I src

all: bpf user

bpf:
	$(CLANG) $(BPF_CFLAGS) \
	-c src/copy_fail_hook.bpf.c \
	-o copy_fail_hook.bpf.o

user:
	gcc src/copy_fail_hook.c \
	-o copy_fail_hook \
	-lbpf

clean:
	rm -f *.o copy_fail_hook
