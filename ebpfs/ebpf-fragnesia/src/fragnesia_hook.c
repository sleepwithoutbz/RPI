#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int libbpf_log_fn(enum libbpf_print_level level, const char *format,
                         va_list args) {
  if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
    return 0;

  return vfprintf(stderr, format, args);
}

static int attach_prog(struct bpf_object *obj, const char *prog_name,
                       struct bpf_link **link) {
  struct bpf_program *prog;
  int err;

  prog = bpf_object__find_program_by_name(obj, prog_name);
  if (!prog) {
    fprintf(stderr, "program not found: %s\n", prog_name);
    return -ENOENT;
  }

  *link = bpf_program__attach(prog);
  err = libbpf_get_error(*link);
  if (err) {
    *link = NULL;
    fprintf(stderr, "attach failed: %s: %s\n", prog_name, strerror(-err));
    return err;
  }

  return 0;
}

int main(void) {
  struct bpf_object *obj;

  const char *prog_names[] = {
      "hook_esp6_input_crypto_decrypt_call",
  };
  struct bpf_link *links[sizeof(prog_names) / sizeof(prog_names[0])] = {};

  int err;
  size_t i;

  setvbuf(stdout, NULL, _IOLBF, 0);

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_log_fn);

  obj = bpf_object__open_file("fragnesia_hook.bpf.o", NULL);

  if (!obj) {
    fprintf(stderr, "open failed\n");
    return 1;
  }

  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "load failed: %d\n", err);
    bpf_object__close(obj);
    return 1;
  }

  for (i = 0; i < sizeof(prog_names) / sizeof(prog_names[0]); i++) {
    err = attach_prog(obj, prog_names[i], &links[i]);
    if (err) {
      while (i > 0)
        bpf_link__destroy(links[--i]);
      bpf_object__close(obj);
      return 1;
    }
  }

  printf("attached: esp6_input+0x1e4\n");

  while (1) {
    sleep(1);
  }

  for (i = 0; i < sizeof(links) / sizeof(links[0]); i++)
    bpf_link__destroy(links[i]);

  bpf_object__close(obj);

  return 0;
}
