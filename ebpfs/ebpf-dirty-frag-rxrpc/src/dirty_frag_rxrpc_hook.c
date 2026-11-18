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

static int attach_prog(struct bpf_object *obj, const char *prog_name, struct bpf_link **link)
{
	struct bpf_program *prog;
	int err;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog)
	{
		fprintf(stderr, "program not found: %s\n", prog_name);
		return -ENOENT;
	}

	*link = bpf_program__attach(prog);
	err = libbpf_get_error(*link);
	if (err)
	{
		*link = NULL;
		fprintf(stderr, "attach failed: %s: %s\n", prog_name, strerror(-err));
		return err;
	}

	return 0;
}

int main(void)
{
	struct bpf_object *obj;

	struct bpf_link *rxkad_call1_link = NULL;
	struct bpf_link *rxkad_call2_link = NULL;

	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_log_fn);

	obj = bpf_object__open_file(
		"dirty_frag_rxrpc_hook.bpf.o",
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

	err = attach_prog(obj, "hook_rxkad_verify_packet_1_skb_to_sgvec", &rxkad_call1_link);
	if (err)
	{
		bpf_object__close(obj);
		return 1;
	}

	err = attach_prog(obj, "hook_rxkad_verify_packet_2_skb_to_sgvec", &rxkad_call2_link);
	if (err)
	{
		bpf_link__destroy(rxkad_call1_link);
		bpf_object__close(obj);
		return 1;
	}

	printf("attached: rxkad_verify_packet_1+0x83, rxkad_verify_packet_2+0x23e\n");

	while (1)
	{
		sleep(1);
	}

	bpf_link__destroy(rxkad_call2_link);
	bpf_link__destroy(rxkad_call1_link);

	bpf_object__close(obj);

	return 0;
}
