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

	struct bpf_link *esp_input_entry_link = NULL;
	struct bpf_link *esp_input_pull_tail_link = NULL;
	struct bpf_link *esp_input_crypto_decrypt_link = NULL;
	struct bpf_link *esp_done2_entry_link = NULL;
	struct bpf_link *esp_done2_copy_bits_link = NULL;
	struct bpf_link *esp_done_esn_entry_link = NULL;
	struct bpf_link *esp_done_esn_restore_link = NULL;

	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_log_fn);

	obj = bpf_object__open_file(
		"dirty_frag_esp_hook.bpf.o",
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

	err = attach_prog(obj, "hook_esp_input_entry", &esp_input_entry_link);
	if (err)
	{
		bpf_object__close(obj);
		return 1;
	}

	err = attach_prog(obj, "hook_esp_input_pull_tail", &esp_input_pull_tail_link);
	if (err)
	{
		bpf_link__destroy(esp_input_entry_link);
		bpf_object__close(obj);
		return 1;
	}

	err = attach_prog(obj, "hook_esp_input_crypto_decrypt", &esp_input_crypto_decrypt_link);
	if (err)
	{
		bpf_link__destroy(esp_input_pull_tail_link);
		bpf_link__destroy(esp_input_entry_link);
		bpf_object__close(obj);
		return 1;
	}

	err = attach_prog(obj, "hook_esp_input_done2_entry", &esp_done2_entry_link);
	if (err)
	{
		bpf_link__destroy(esp_input_crypto_decrypt_link);
		bpf_link__destroy(esp_input_pull_tail_link);
		bpf_link__destroy(esp_input_entry_link);
		bpf_object__close(obj);
		return 1;
	}

	err = attach_prog(obj, "hook_esp_input_done2_skb_copy_bits", &esp_done2_copy_bits_link);
	if (err)
	{
		bpf_link__destroy(esp_done2_entry_link);
		bpf_link__destroy(esp_input_crypto_decrypt_link);
		bpf_link__destroy(esp_input_pull_tail_link);
		bpf_link__destroy(esp_input_entry_link);
		bpf_object__close(obj);
		return 1;
	}

	// err = attach_prog(obj, "hook_esp_input_done_esn_restore_header", &esp_done_esn_restore_link);
	// if (err)
	// {
	// 	bpf_link__destroy(esp_done2_copy_bits_link);
	// 	bpf_link__destroy(esp_done2_entry_link);
	// 	bpf_link__destroy(esp_input_crypto_decrypt_link);
	// 	bpf_link__destroy(esp_input_pull_tail_link);
	// 	bpf_link__destroy(esp_input_entry_link);
	// 	bpf_object__close(obj);
	// 	return 1;
	// }

	printf("attached: esp_input, esp_input+0x305, esp_input+0x1e4, esp_input_done2, esp_input_done2+0x110, esp_input_done_esn+0x5\n");

	while (1)
	{
		sleep(1);
	}

	// bpf_link__destroy(esp_done_esn_restore_link);
	bpf_link__destroy(esp_done2_copy_bits_link);
	bpf_link__destroy(esp_done2_entry_link);
	bpf_link__destroy(esp_input_crypto_decrypt_link);
	bpf_link__destroy(esp_input_pull_tail_link);
	bpf_link__destroy(esp_input_entry_link);

	bpf_object__close(obj);

	return 0;
}
