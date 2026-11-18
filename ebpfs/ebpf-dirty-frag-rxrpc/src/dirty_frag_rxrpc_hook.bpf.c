#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

extern int bpf_jmp_to(struct pt_regs *regs, unsigned long ip) __ksym;
extern int bpf_set_regs(struct pt_regs *regs, const void *src, u32 src__sz) __ksym;

#define SG_CHAIN 0x01UL
#define SG_END 0x02UL
#define PAGE_MAPPING_ANON 0x1UL
#define PAGE_MAPPING_FLAGS 0x3UL
#define MAX_SG_DUMP 16
#define MAX_SKB_FRAGS 17
#define FMODE_READ 0x1
#define FMODE_WRITE 0x2
#define PROT_WRITE 0x2
#define EACCES 13
#define NOACCESS_ERR (-EACCES)
#define KPROBE_INT3_SIZE 1UL
#define CALL_INSN_SIZE 5UL
#define RXKAD_VERIFY_PACKET_1_SKB_TO_SGVEC_OFF 0x83UL
#define RXKAD_VERIFY_PACKET_2_SKB_TO_SGVEC_OFF 0x23EUL
#define AEAD_RECVMSG_RET_THUNK_OFF 0x224UL
#define AEAD_RECVMSG_GET_RSGL_RET_OFF 0x11DUL
#define AEAD_RECVMSG_DECRYPT_AIO_OFF 0x388UL
#define AEAD_RECVMSG_DECRYPT_SYNC_OFF 0x542UL
#define AF_ALG_ASYNC_REQ_FIRST_RSGL_OFF 0x10UL
#define AF_ALG_RSGL_SGT_SGL_OFF 0x0UL
#define AF_ALG_CTX_TSGL_LIST_OFF 0x0UL
#define AF_ALG_TSGL_CUR_OFF 0x10UL
#define AF_ALG_TSGL_SG_OFF 0x18UL

#include "../../include/inode_ugo.bpf.h"
#include "../../include/skb_frag.bpf.h"

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

/*
 * inspect_sg - walk a scatterlist and check every page for write permission.
 *
 * Returns NOACCESS_ERR if any page belongs to a file the current process is
 * not allowed to write to (indicating a possible page-cache tampering attack).
 * Returns 0 if all pages pass or the scatterlist is empty.
 */
static __always_inline int inspect_sg(struct scatterlist *sg, const char *op) {
	struct scatterlist *sg_iter = sg;
	__u32 payload_idx = 0;

	if (!sg)
		return 0;

// #pragma unroll
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

static __always_inline void dump_sg_pages(struct scatterlist *sg, const char *op) {
	struct scatterlist *sg_iter = sg;

	if (!sg)
		return;

	for (int i = 0; i < MAX_SG_DUMP; i++) {
		struct address_space *mapping;
		struct inode *inode = 0;
		struct page *page;
		unsigned long mapping_raw = 0;
		unsigned long page_link;
		__u32 is_anon = 0;
		__u32 length;
		__u32 offset;

		if (!sg_iter)
			break;

		page_link = BPF_CORE_READ(sg_iter, page_link);
		length = BPF_CORE_READ(sg_iter, length);
		offset = BPF_CORE_READ(sg_iter, offset);
		page = (struct page *)(page_link & ~(SG_CHAIN | SG_END));
		if (page)
			mapping_raw = (unsigned long)BPF_CORE_READ(page, mapping);

		mapping = page_mapping_ptr(page, &is_anon);
		if (mapping)
			inode = BPF_CORE_READ(mapping, host);

		bpf_printk("%s sg[%d]=%lx page=%lx\n",
			   op, i, (unsigned long)sg_iter, (unsigned long)page);
		bpf_printk("%s len=%u off=%u link=%lx\n",
			   op, length, offset, page_link);
		bpf_printk("%s mapping=%lx anon=%u ino=%llu\n",
			   op, mapping_raw, is_anon,
			   inode ? BPF_CORE_READ(inode, i_ino) : 0);

		if (page_link & SG_END)
			break;
		sg_iter = sg_next_ptr(sg_iter);
	}
}

static __always_inline void dump_sg_entry(struct scatterlist *sg, const char *op,
					  __u32 idx) {
	struct address_space *mapping;
	struct inode *inode = 0;
	struct page *page;
	unsigned long mapping_raw = 0;
	unsigned long page_link;
	__u32 is_anon = 0;
	__u32 length;
	__u32 offset;

	if (!sg)
		return;

	page_link = BPF_CORE_READ(sg, page_link);
	length = BPF_CORE_READ(sg, length);
	offset = BPF_CORE_READ(sg, offset);
	page = (struct page *)(page_link & ~(SG_CHAIN | SG_END));
	if (page)
		mapping_raw = (unsigned long)BPF_CORE_READ(page, mapping);

	mapping = page_mapping_ptr(page, &is_anon);
	if (mapping)
		inode = BPF_CORE_READ(mapping, host);

	bpf_printk("%s sg[%u]=%lx page=%lx\n",
		   op, idx, (unsigned long)sg, (unsigned long)page);
	bpf_printk("%s len=%u off=%u link=%lx\n",
		   op, length, offset, page_link);
	bpf_printk("%s mapping=%lx anon=%u ino=%llu\n",
		   op, mapping_raw, is_anon,
		   inode ? BPF_CORE_READ(inode, i_ino) : 0);
}

static __always_inline int inspect_sg_array(struct scatterlist *sg,
					    __u32 nr,
					    const char *op) {
	if (!sg)
		return 0;

	for (int i = 0; i < MAX_SG_DUMP; i++) {
		struct scatterlist *entry;

		if ((__u32)i >= nr)
			break;

		entry = sg + i;
		if (BPF_CORE_READ(entry, length) > 0) {
			dump_sg_entry(entry, op, i);
			if (check_page_perm(entry, i, op))
				return NOACCESS_ERR;
		}
	}

	return 0;
}

static __always_inline int inspect_tsgl_list(unsigned long ctx, const char *op) {
	unsigned long head = ctx + AF_ALG_CTX_TSGL_LIST_OFF;
	unsigned long node = 0;

	if (!ctx)
		return 0;

	bpf_probe_read_kernel(&node, sizeof(node), (void *)head);
	for (int list_idx = 0; list_idx < MAX_SG_DUMP; list_idx++) {
		struct scatterlist *sg;
		__u32 cur = 0;

		if (!node || node == head)
			break;

		bpf_probe_read_kernel(&cur, sizeof(cur),
				      (void *)(node + AF_ALG_TSGL_CUR_OFF));
		sg = (struct scatterlist *)(node + AF_ALG_TSGL_SG_OFF);
		if (inspect_sg_array(sg, cur, op) == NOACCESS_ERR)
			return NOACCESS_ERR;

		bpf_probe_read_kernel(&node, sizeof(node), (void *)node);
	}

	return 0;
}

/*
 * rxkad_verify_packet has two skb_to_sgvec() call sites:
 *
 *   rxkad_verify_packet_1 inline, rxkad.c:447
 *   rxkad_verify_packet_2 inline, rxkad.c:524
 *
 * These probes run at the call instruction, before skb_to_sgvec() populates the
 * scatterlist. Inspect the skb page fragments directly and, on denial, skip the
 * call instruction with %rax set to -EACCES so the caller follows its existing
 * skb_to_sgvec() error path.
 */
static __always_inline int inspect_skb_range(struct sk_buff *skb, int offset,
					     int len, const char *op) {
	struct skb_shared_info *shinfo;
	unsigned int skb_len;
	unsigned int data_len;
	unsigned int head_len;
	unsigned int range_start;
	unsigned int range_end;
	unsigned int pos;
	unsigned char *head;
	__u8 nr_frags;

	if (!skb || offset < 0 || len <= 0)
		return 0;

	skb_len = BPF_CORE_READ(skb, len);
	data_len = BPF_CORE_READ(skb, data_len);
	if (data_len > skb_len)
		return 0;

	range_start = (__u32)offset;
	if (range_start >= skb_len)
		return 0;

	range_end = range_start + (__u32)len;
	if (range_end < range_start || range_end > skb_len)
		range_end = skb_len;

	head_len = skb_len - data_len;
	if (range_end <= head_len)
		return 0;

	head = BPF_CORE_READ(skb, head);
	if (!head)
		return 0;

	shinfo = (struct skb_shared_info *)(head + BPF_CORE_READ(skb, end));
	nr_frags = BPF_CORE_READ(shinfo, nr_frags);
	if (nr_frags > MAX_SKB_FRAGS)
		nr_frags = MAX_SKB_FRAGS;

	pos = head_len;
	for (int i = 0; i < MAX_SKB_FRAGS; i++) {
		struct skb_frag___pagecache *frag;
		struct page *page;
		unsigned int frag_len;
		unsigned int frag_end;

		if ((__u8)i >= nr_frags)
			break;

		frag = pagecache_skb_frag(shinfo, i);
		if (BPF_CORE_READ_INTO(&frag_len, frag, len))
			return NOACCESS_ERR;
		frag_end = pos + frag_len;
		if (frag_end < pos)
			break;

		if (range_start < frag_end && range_end > pos) {
			if (pagecache_skb_frag_page(frag, &page))
				return NOACCESS_ERR;
			if (check_page_perm_ptr(page, i, op))
				return NOACCESS_ERR;
		}

		pos = frag_end;
		if (pos >= range_end)
			break;
	}

	return 0;
}

static __always_inline int rxkad_skip_skb_to_sgvec(struct pt_regs *ctx,
						   struct sk_buff *skb,
						   int offset,
						   int len,
						   const char *hook_name) {
	if (inspect_skb_range(skb, offset, len, hook_name) == NOACCESS_ERR) {
		struct pt_regs regs = {};
		unsigned long cur_ip = BPF_CORE_READ(ctx, ip);
		unsigned long next_ip = cur_ip + CALL_INSN_SIZE - KPROBE_INT3_SIZE;

		copy_pt_regs(&regs, ctx);
		regs.ax = (unsigned long)NOACCESS_ERR;
		bpf_set_regs(ctx, &regs, sizeof(regs));
		bpf_jmp_to(ctx, next_ip);
		bpf_printk("%s skip skb_to_sgvec err=%d\n", hook_name, NOACCESS_ERR);
		return 1;
	}

	return 0;
}

SEC("kprobe/rxkad_verify_packet_1+0x83")
int hook_rxkad_verify_packet_1_skb_to_sgvec(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	int offset = (int)PT_REGS_PARM3(ctx);
	int len = (int)PT_REGS_PARM4(ctx);

	return rxkad_skip_skb_to_sgvec(ctx, skb, offset, len,
				       "rxkad_verify_packet_1+0x83");
}

SEC("kprobe/rxkad_verify_packet_2+0x23e")
int hook_rxkad_verify_packet_2_skb_to_sgvec(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	int offset = (int)PT_REGS_PARM3(ctx);
	int len = (int)PT_REGS_PARM4(ctx);

	return rxkad_skip_skb_to_sgvec(ctx, skb, offset, len,
				       "rxkad_verify_packet_2+0x23e");
}
