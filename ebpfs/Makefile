DEFENSES := ebpf-copy-fail ebpf-dirty-decrypt ebpf-dirty-frag-esp \
            ebpf-dirty-frag-rxrpc ebpf-fragnesia
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
STAGE_DIR ?= ../macro_test/ebpf

.PHONY: all headers stage clean $(DEFENSES)

all: $(DEFENSES)

$(DEFENSES):
	$(MAKE) -C $@

headers:
	@set -eu; \
	tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(BPFTOOL) btf dump file "$(VMLINUX_BTF)" format c > "$$tmp"; \
	for dir in $(DEFENSES); do \
		cp "$$tmp" "$$dir/src/vmlinux.h"; \
	done

stage: all
	mkdir -p "$(STAGE_DIR)"
	@set -eu; for dir in $(DEFENSES); do \
		cp "$$dir/"*_hook "$$dir/"*_hook.bpf.o "$(STAGE_DIR)/"; \
	done

clean:
	@set -eu; for dir in $(DEFENSES); do $(MAKE) -C "$$dir" clean; done
