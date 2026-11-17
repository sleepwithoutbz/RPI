#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_jmp_to(struct pt_regs *regs, unsigned long ip) __ksym;
extern int bpf_set_regs(struct pt_regs *regs, const void *src,
                        u32 src__sz) __ksym;
extern int bpf_skip_call(struct pt_regs *regs, unsigned long retval,
                         u32 call_size) __ksym;

#define SG_CHAIN 0x01UL
#define SG_END 0x02UL
#define PAGE_MAPPING_ANON 0x1UL
#define PAGE_MAPPING_FLAGS 0x3UL
#define MAX_SG_DUMP 32
#define FMODE_READ 0x1
#define FMODE_WRITE 0x2
#define PROT_WRITE 0x2
#define EACCES 13
#define NOACCESS_ERR (-EACCES)
#define KPROBE_INT3_SIZE 1UL
#define CALL_SIZE 5
#define MAX_SKB_FRAGS_TO_SCAN 17
#define MAX_SKB_DONE2_FRAGS_TO_SCAN 8
#define MAX_SKB_FRAG_LIST_TO_SCAN 8
#define ESP6_INPUT_RET_THUNK_OFF 0x237UL
#define ESP6_INPUT_PSKB_PULL_TAIL_CALL_OFF 0x2faUL
#define ESP6_INPUT_CRYPTO_DECRYPT_CALL_OFF 0x1e4UL
#define ESP6_INPUT_RESTORE_HEADER_OFF 0x2b8UL
#define ESP6_INPUT_DONE2_RET_THUNK_OFF 0x222UL
#define ESP6_INPUT_DONE2_SKB_COPY_BITS_OFF 0x120UL
#define ESP6_INPUT_TAIL_RET_THUNK_OFF 0x9bUL
#define ESP6_INPUT_TAIL_PSKB_PULL_TAIL_CALL_OFF 0xb9UL

#include "../../include/inode_ugo.bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct pt_regs);
} aead_entry_regs SEC(".maps");

static __always_inline __u32 current_tgid(void) {
  return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline void copy_pt_regs(struct pt_regs *dst,
                                         const struct pt_regs *src) {
  dst->r15 = BPF_CORE_READ(src, r15);
  dst->r14 = BPF_CORE_READ(src, r14);
  dst->r13 = BPF_CORE_READ(src, r13);
  dst->r12 = BPF_CORE_READ(src, r12);
  dst->bp = BPF_CORE_READ(src, bp);
  dst->bx = BPF_CORE_READ(src, bx);
  dst->r11 = BPF_CORE_READ(src, r11);
  dst->r10 = BPF_CORE_READ(src, r10);
  dst->r9 = BPF_CORE_READ(src, r9);
  dst->r8 = BPF_CORE_READ(src, r8);
  dst->ax = BPF_CORE_READ(src, ax);
  dst->cx = BPF_CORE_READ(src, cx);
  dst->dx = BPF_CORE_READ(src, dx);
  dst->si = BPF_CORE_READ(src, si);
  dst->di = BPF_CORE_READ(src, di);
  dst->orig_ax = BPF_CORE_READ(src, orig_ax);
  dst->ip = BPF_CORE_READ(src, ip);
  dst->cs = BPF_CORE_READ(src, cs);
  dst->flags = BPF_CORE_READ(src, flags);
  dst->sp = BPF_CORE_READ(src, sp);
  dst->ss = BPF_CORE_READ(src, ss);
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

static __always_inline int inspect_sg_log_only(struct scatterlist *sg,
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

  if (inspect_sg_log_only(sg, "esp6_input+0x1e4") == NOACCESS_ERR)
    bpf_skip_call(ctx, (unsigned long)NOACCESS_ERR, CALL_SIZE);

  return 0;
}
