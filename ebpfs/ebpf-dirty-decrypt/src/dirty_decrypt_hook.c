#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int libbpf_log_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
		return 0;

	return vfprintf(stderr, format, args);
}

static int attach_kprobe_site(struct bpf_object *obj, const char *prog_name,
			      const char *func_name, size_t offset,
			      struct bpf_link **link)
{
	LIBBPF_OPTS(bpf_kprobe_opts, opts,
		    .offset = offset,
		    .attach_mode = PROBE_ATTACH_MODE_LEGACY);
	struct bpf_program *prog;
	int err;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog)
	{
		fprintf(stderr, "program not found: %s\n", prog_name);
		return -ENOENT;
	}

	*link = bpf_program__attach_kprobe_opts(prog, func_name, &opts);
	err = libbpf_get_error(*link);
	if (err)
	{
		*link = NULL;
		fprintf(stderr, "attach failed: %s: %s+0x%zx: %s\n",
			prog_name, func_name, offset, strerror(-err));
		return err;
	}

	return 0;
}

int main(void)
{
	struct bpf_object *obj;

	struct bpf_link *rxgk_verify_copy_bits_call_link = NULL;
	struct bpf_link *rxgk_verify_mic_call_link = NULL;

	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_log_fn);

	obj = bpf_object__open_file(
		"dirty_decrypt_hook.bpf.o",
		NULL);

	if (!obj)
	{
		fprintf(stderr, "open failed\n");
		return 1;
	}

	err = bpf_object__load(obj);
	if (err)
	{
		fprintf(stderr, "load failed: %d\n", err);
		bpf_object__close(obj);
		return 1;
	}

	err = attach_kprobe_site(obj, "hook_rxgk_verify_packet_skb_copy_bits_call",
				 "rxgk_verify_packet", 0x134,
				 &rxgk_verify_copy_bits_call_link);
	if (err)
	{
		bpf_object__close(obj);
		return 1;
	}

	err = attach_kprobe_site(obj, "hook_rxgk_verify_packet_verify_mic_call",
				 "rxgk_verify_packet", 0x2d3,
				 &rxgk_verify_mic_call_link);
	if (err)
	{
		bpf_link__destroy(rxgk_verify_copy_bits_call_link);
		bpf_object__close(obj);
		return 1;
	}

	printf("attached: rxgk_verify_packet+0x134, rxgk_verify_packet+0x2d3\n");

	while (1)
	{
		sleep(1);
	}

	bpf_link__destroy(rxgk_verify_mic_call_link);
	bpf_link__destroy(rxgk_verify_copy_bits_call_link);

	bpf_object__close(obj);

	return 0;
}
