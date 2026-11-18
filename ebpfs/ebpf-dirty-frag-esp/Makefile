CLANG ?= clang
ARCH ?= $(shell uname -m)

ifneq ($(ARCH),x86_64)
$(error These guards require the evaluated x86-64 kernel/module build)
endif
TARGET_ARCH := x86

.PHONY: all bpf user clean

BPF_CFLAGS := \
    -O2 \
    -g \
    -target bpf \
    -D__TARGET_ARCH_$(TARGET_ARCH) \
    -I src

all: bpf user

bpf: src/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
	-c src/dirty_frag_hook.bpf.c \
	-o dirty_frag_esp_hook.bpf.o

src/vmlinux.h:
	@echo "Generate headers first: make -C .. headers" >&2
	@exit 1

user:
	gcc src/dirty_frag_hook.c \
	-o dirty_frag_esp_hook \
	-lbpf

clean:
	rm -f *.o dirty_frag_esp_hook
