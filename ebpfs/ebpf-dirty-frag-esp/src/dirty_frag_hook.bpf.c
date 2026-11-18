#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_jmp_to(struct pt_regs *regs, unsigned long ip) __ksym;
extern int bpf_set_regs(struct pt_regs *regs, const void *src, u32 src__sz) __ksym;
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
#define MAX_SKB_DONE2_FRAGS_TO_SCAN 4
#define ESP_INPUT_RET_THUNK_OFF 0x23dUL
#define ESP_INPUT_CRYPTO_DECRYPT_OFF 0x1e4UL
#define ESP_INPUT_DONE2_RET_THUNK_OFF 0x1dfUL
#define ESP_INPUT_DONE2_SKB_COPY_BITS_OFF 0x110UL

#include "../../include/inode_ugo.bpf.h"
#include "../../include/skb_frag.bpf.h"

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

static __always_inline struct scatterlist *sg_next_ptr(const struct scatterlist *sg) {
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

static __always_inline struct address_space *page_mapping_ptr(struct page *page, __u32 *is_anon) {
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

static __always_inline int check_inode_perm(struct inode *inode, __u32 idx,
                                            const char *op, __u32 page_is_anon) {
    __u32 tgid = current_tgid();

    if (inode_ugo_check(inode, UGO_MAY_WRITE) != 0) {
        bpf_printk("%s UGO denied tgid=%u idx=%u", op, tgid, idx);
        return NOACCESS_ERR;
    }
    return 0;
}

static __always_inline int check_page_perm_ptr(struct page *page,
					       __u32 idx,
					       const char *op) {
	struct address_space *mapping;
	struct inode *inode;
	__u32 is_anon = 0;

	mapping = page_mapping_ptr(page, &is_anon);
	if (!mapping)
		return 0;

	inode = BPF_CORE_READ(mapping, host);
	if (!inode)
		return NOACCESS_ERR;

	return check_inode_perm(inode, idx, op, is_anon);
}

static __always_inline int check_page_perm(const struct scatterlist *sg,
					   __u32 idx,
					   const char *op) {
	if (!sg)
		return 0;

	return check_page_perm_ptr(sg_page_ptr(sg), idx, op);
}

static __always_inline struct skb_shared_info *skb_shinfo_ptr(struct sk_buff *skb) {
	unsigned char *head;
	sk_buff_data_t end;

	if (!skb)
		return 0;

	head = BPF_CORE_READ(skb, head);
	end = BPF_CORE_READ(skb, end);
	if (!head)
		return 0;

	return (struct skb_shared_info *)(head + end);
}

static __always_inline int inspect_skb(struct sk_buff *skb, const char *op) {
	struct skb_shared_info *shinfo;
	__u8 nr_frags;

	shinfo = skb_shinfo_ptr(skb);
	if (!shinfo)
		return 0;

	nr_frags = BPF_CORE_READ(shinfo, nr_frags);
	if (nr_frags > MAX_SKB_FRAGS_TO_SCAN)
		nr_frags = MAX_SKB_FRAGS_TO_SCAN;

	for (int i = 0; i < MAX_SKB_FRAGS_TO_SCAN; i++) {
		struct skb_frag___pagecache *frag;
		struct page *page;
		unsigned int len;

		if (i >= nr_frags)
			break;

		frag = pagecache_skb_frag(shinfo, i);
		if (BPF_CORE_READ_INTO(&len, frag, len))
			return NOACCESS_ERR;
		if (!len)
			continue;

		if (pagecache_skb_frag_page(frag, &page))
			return NOACCESS_ERR;
		if (check_page_perm_ptr(page, i, op))
			return NOACCESS_ERR;
	}

	return 0;
}

static __always_inline int inspect_skb_done2(struct sk_buff *skb,
					     const char *op) {
	struct skb_shared_info *shinfo;
	__u8 nr_frags;

	shinfo = skb_shinfo_ptr(skb);
	if (!shinfo)
		return 0;

	nr_frags = BPF_CORE_READ(shinfo, nr_frags);

#pragma unroll
	for (int i = 0; i < MAX_SKB_DONE2_FRAGS_TO_SCAN; i++) {
		struct skb_frag___pagecache *frag;
		struct page *page;
		unsigned int len;

		if (i >= nr_frags)
			return 0;

		frag = pagecache_skb_frag(shinfo, i);
		if (BPF_CORE_READ_INTO(&len, frag, len))
			return NOACCESS_ERR;
		if (!len)
			continue;

		if (pagecache_skb_frag_page(frag, &page))
			return NOACCESS_ERR;
		if (check_page_perm_ptr(page, i, op))
			return NOACCESS_ERR;
	}

	return 0;
}

static __always_inline int inspect_sg(struct scatterlist *sg, const char *op) {
	struct scatterlist *sg_iter = sg;
	__u32 payload_idx = 0;

	if (!sg)
		return 0;

	for (int i = 0; i < MAX_SG_DUMP; i++) {
		if (!sg_iter)
			break;

		if (BPF_CORE_READ(sg_iter, length) > 0) {
			if (check_page_perm(sg_iter, payload_idx, op))
				return NOACCESS_ERR;
			payload_idx++;
		}
		sg_iter = sg_next_ptr(sg_iter);
	}

	return 0;
}

static __always_inline void save_entry_regs(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pt_regs regs = {};

	copy_pt_regs(&regs, ctx);
	bpf_map_update_elem(&aead_entry_regs, &pid_tgid, &regs, BPF_ANY);
}

static __always_inline int do_skb_hook_action(struct pt_regs *ctx,
					      struct sk_buff *skb,
					      const char *hook_name,
					      unsigned long hook_off,
					      unsigned long ret_off,
					      unsigned long retval) {
	if (inspect_skb_done2(skb, hook_name) == NOACCESS_ERR) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		struct pt_regs *saved;
		unsigned long base;
		unsigned long ret_ip;
		unsigned long cur_ip;

		saved = bpf_map_lookup_elem(&aead_entry_regs, &pid_tgid);
		if (!saved)
			return 0;

		cur_ip = BPF_CORE_READ(ctx, ip);
		base = cur_ip - hook_off - KPROBE_INT3_SIZE;
		ret_ip = base + ret_off;

		saved->ax = retval;
		bpf_set_regs(ctx, saved, sizeof(*saved));
		bpf_jmp_to(ctx, ret_ip);
		return 1;
	}

	return 0;
}

static __always_inline int do_sg_hook_action(struct pt_regs *ctx,
					     struct scatterlist *sg,
					     const char *hook_name,
					     unsigned long hook_off,
					     unsigned long ret_off,
					     unsigned long retval) {
	if (inspect_sg(sg, hook_name) == NOACCESS_ERR) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		struct pt_regs *saved;
		unsigned long base;
		unsigned long ret_ip;
		unsigned long cur_ip;

		saved = bpf_map_lookup_elem(&aead_entry_regs, &pid_tgid);
		if (!saved)
			return 0;

		cur_ip = BPF_CORE_READ(ctx, ip);
		base = cur_ip - hook_off - KPROBE_INT3_SIZE;
		ret_ip = base + ret_off;

		saved->ax = retval;
		bpf_set_regs(ctx, saved, sizeof(*saved));
		bpf_jmp_to(ctx, ret_ip);
		return 1;
	}

	return 0;
}

static __always_inline int do_sg_skip_call_action(struct pt_regs *ctx,
						  struct scatterlist *sg,
						  const char *hook_name,
						  unsigned long retval) {
	if (inspect_sg(sg, hook_name) == NOACCESS_ERR) {
		bpf_skip_call(ctx, retval, CALL_SIZE);
		return 1;
	}

	return 0;
}

SEC("kprobe/esp_input")
int hook_esp_input_entry(struct pt_regs *ctx) {
	save_entry_regs(ctx);
	return 0;
}

/*
 * This is the actual in-place ESP decrypt write point:
 * aead_request_set_crypt(req, sg, sg, ...); crypto_aead_decrypt(req).
 * req->dst is the SGL generated by skb_to_sgvec(), so it covers skb linear
 * data, paged frags, and frag_list entries.
 *
 * Experimental direct-return mode: after detecting a protected page, restore
 * the esp_input entry registers, set the return value, and jump to esp_input's
 * final return thunk.
 */
SEC("kprobe/esp_input+0x1e4")
int hook_esp_input_crypto_decrypt(struct pt_regs *ctx) {
	struct aead_request *req = (struct aead_request *)PT_REGS_PARM1(ctx);
	struct scatterlist *sg = BPF_CORE_READ(req, dst);

	return do_sg_hook_action(ctx, sg, "esp_input+0x1e4",
				 ESP_INPUT_CRYPTO_DECRYPT_OFF,
				 ESP_INPUT_RET_THUNK_OFF,
				 (unsigned long)NOACCESS_ERR);
}

SEC("kprobe/esp_input_done2")
int hook_esp_input_done2_entry(struct pt_regs *ctx) {
	save_entry_regs(ctx);
	return 0;
}

/* esp_remove_trailer() inlined into esp_input_done2: call skb_copy_bits(). */
SEC("kprobe/esp_input_done2+0x110")
int hook_esp_input_done2_skb_copy_bits(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

	return do_skb_hook_action(ctx, skb, "esp_input_done2+0x110",
				  ESP_INPUT_DONE2_SKB_COPY_BITS_OFF,
				  ESP_INPUT_DONE2_RET_THUNK_OFF,
				  (unsigned long)NOACCESS_ERR);
}
