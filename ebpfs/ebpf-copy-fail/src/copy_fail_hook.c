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

	const char *names[] = {
		"hook_aead_recvmsg_11d", "hook_aead_decrypt_aio",
		"hook_aead_encrypt_sync", "hook_aead_decrypt_sync",
		"hook_aead_encrypt_aio",
	};
	struct bpf_link *links[sizeof(names) / sizeof(names[0])] = {};
	size_t i;

	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_log_fn);

	obj = bpf_object__open_file(
		"copy_fail_hook.bpf.o",
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

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		err = attach_prog(obj, names[i], &links[i]);
		if (err) {
			while (i) bpf_link__destroy(links[--i]);
			bpf_object__close(obj);
			return 1;
		}
	}
	printf("attached: aead_recvmsg+0x11d, +0x383, +0x3f6, +0x542, +0x577\n");

	while (1)
	{
		sleep(1);
	}

	for (i = 0; i < sizeof(links) / sizeof(links[0]); i++)
		bpf_link__destroy(links[i]);

	bpf_object__close(obj);

	return 0;
}
