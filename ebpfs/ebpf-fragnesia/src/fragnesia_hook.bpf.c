#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_skip_call(struct pt_regs *regs, unsigned long retval,
                         u32 call_size) __ksym;

#define SG_CHAIN 0x01UL
#define SG_END 0x02UL
#define PAGE_MAPPING_ANON 0x1UL
#define PAGE_MAPPING_FLAGS 0x3UL
#define MAX_SG_DUMP 32
#define EACCES 13
#define NOACCESS_ERR (-EACCES)
#define CALL_SIZE 5

#include "../../include/inode_ugo.bpf.h"

static __always_inline __u32 current_tgid(void) {
  return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline struct page *sg_page_ptr(const struct scatterlist *sg) {
  unsigned long page_link = BPF_CORE_READ(sg, page_link);

  return (struct page *)(page_link & ~(SG_CHAIN | SG_END));
}

static __always_inline __u32 sg_is_last(const struct scatterlist *sg) {
  unsigned long page_link = BPF_CORE_READ(sg, page_link);

  return !!(page_link & SG_END);
}

static __always_inline struct scatterlist *
sg_next_ptr(const struct scatterlist *sg) {
  struct scatterlist *next;
  unsigned long page_link;

  if (!sg || sg_is_last(sg))
    return 0;

  next = (struct scatterlist *)(sg + 1);
  page_link = BPF_CORE_READ(next, page_link);
  if (page_link & SG_CHAIN)
    return (struct scatterlist *)(page_link & ~SG_CHAIN);

  return next;
}

static __always_inline struct address_space *page_mapping_ptr(struct page *page,
                                                              __u32 *is_anon) {
  unsigned long mapping_raw;

  if (!page)
    return 0;

  mapping_raw = (unsigned long)BPF_CORE_READ(page, mapping);
  if (is_anon)
    *is_anon = !!(mapping_raw & PAGE_MAPPING_ANON);
  if (!mapping_raw || (mapping_raw & PAGE_MAPPING_ANON))
    return 0;

  return (struct address_space *)(mapping_raw & ~PAGE_MAPPING_FLAGS);
}

static __always_inline int inspect_sg(struct scatterlist *sg,
                                       const char *op) {
  struct scatterlist *sg_iter = sg;
  __u32 payload_idx = 0;

  if (!sg)
    return 0;

  for (int i = 0; i < MAX_SG_DUMP; i++) {
    struct page *page;
    struct address_space *mapping;
    struct inode *inode;
    unsigned int len;
    __u32 is_anon = 0;
    __u32 tgid;

    if (!sg_iter)
      break;

    len = BPF_CORE_READ(sg_iter, length);
    if (!len) {
      sg_iter = sg_next_ptr(sg_iter);
      continue;
    }

    page = sg_page_ptr(sg_iter);
    mapping = page_mapping_ptr(page, &is_anon);
    if (!mapping) {
      sg_iter = sg_next_ptr(sg_iter);
      payload_idx++;
      continue;
    }

    inode = BPF_CORE_READ(mapping, host);
    if (!inode)
      return NOACCESS_ERR;

    tgid = current_tgid();
    if (inode_ugo_check(inode, UGO_MAY_WRITE) != 0) {
      bpf_printk("%s UGO denied tgid=%u idx=%u", op, tgid, payload_idx);
      return NOACCESS_ERR;
    }

    sg_iter = sg_next_ptr(sg_iter);
    payload_idx++;
  }

  return 0;
}

SEC("kprobe/esp6_input+0x1e4")
int hook_esp6_input_crypto_decrypt_call(struct pt_regs *ctx) {
  struct aead_request *req = (struct aead_request *)PT_REGS_PARM1(ctx);
  struct scatterlist *sg = BPF_CORE_READ(req, dst);

  if (inspect_sg(sg, "esp6_input+0x1e4") == NOACCESS_ERR)
    bpf_skip_call(ctx, (unsigned long)NOACCESS_ERR, CALL_SIZE);

  return 0;
}
