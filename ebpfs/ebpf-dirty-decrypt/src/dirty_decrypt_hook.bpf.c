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
#define MAX_SG_DUMP 16
#define FMODE_READ 0x1
#define FMODE_WRITE 0x2
#define PROT_WRITE 0x2
#define EACCES 13
#define NOACCESS_ERR (-EACCES)
#define AEAD_RECVMSG_RET_THUNK_OFF 0x224UL
#define AEAD_RECVMSG_GET_RSGL_RET_OFF 0x11DUL
#define AEAD_RECVMSG_DECRYPT_AIO_OFF 0x388UL
#define AEAD_RECVMSG_DECRYPT_SYNC_OFF 0x542UL
#define RXGK_VERIFY_PACKET_SKB_COPY_BITS_CALL_OFF 0x134UL
#define RXGK_VERIFY_PACKET_VERIFY_MIC_CALL_OFF 0x2D3UL
#define RXGK_CALL_INSN_SIZE 5U
#define AF_ALG_ASYNC_REQ_FIRST_RSGL_OFF 0x10UL
#define AF_ALG_RSGL_SGT_SGL_OFF 0x0UL
#define AF_ALG_CTX_TSGL_LIST_OFF 0x0UL
#define AF_ALG_TSGL_CUR_OFF 0x10UL
#define AF_ALG_TSGL_SG_OFF 0x18UL

#include "../../include/inode_ugo.bpf.h"
#include "../../include/skb_frag.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct pt_regs);
} aead_entry_regs SEC(".maps");

#if 0
/* Disabled iov_iter experiment helpers; not used by active hooks. */
struct vma_perm_ctx {
	const char *op;
	__u64 addr;
	__u32 idx;
	int ret;
};
#endif

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

static __always_inline int inspect_skb_frags(struct sk_buff *skb, const char *op) {
	struct skb_shared_info *shinfo;
	__u8 nr_frags;

	shinfo = skb_shinfo_ptr(skb);
	if (!shinfo)
		return 0;

	nr_frags = BPF_CORE_READ(shinfo, nr_frags);
	for (int i = 0; i < MAX_SG_DUMP; i++) {
		struct skb_frag___pagecache *frag;
		struct page *page;

		if ((__u8)i >= nr_frags)
			break;

		frag = pagecache_skb_frag(shinfo, i);
		if (pagecache_skb_frag_page(frag, &page))
			return NOACCESS_ERR;
		if (check_page_perm_ptr(page, i, op))
			return NOACCESS_ERR;
	}

	return 0;
}

static __always_inline int inspect_skb_pages(struct sk_buff *skb, const char *op) {
	struct skb_shared_info *shinfo;
	struct sk_buff *frag_list;

	if (!skb)
		return 0;

	if (inspect_skb_frags(skb, op) == NOACCESS_ERR)
		return NOACCESS_ERR;

	shinfo = skb_shinfo_ptr(skb);
	if (!shinfo)
		return 0;

	frag_list = BPF_CORE_READ(shinfo, frag_list);
	for (int i = 0; i < MAX_SG_DUMP; i++) {
		struct sk_buff *next;

		if (!frag_list)
			break;
		if (inspect_skb_frags(frag_list, op) == NOACCESS_ERR)
			return NOACCESS_ERR;

		next = BPF_CORE_READ(frag_list, next);
		frag_list = next;
	}

	return 0;
}

static __always_inline int deny_rxgk_call(struct pt_regs *ctx,
					  const char *hook_name) {
	bpf_skip_call(ctx, (unsigned long)NOACCESS_ERR, RXGK_CALL_INSN_SIZE);
	bpf_printk("%s skip call ret=%d\n", hook_name, NOACCESS_ERR);
	return 1;
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
 * These hooks are deliberately placed at call sites inside rxgk_verify_packet.
 * They do not probe skb_to_sgvec(), skb_copy_bits(), or crypto helpers
 * globally.  Offsets are for the current 6.17.0+ vmlinux build:
 *
 *   rxgk_verify_packet+0x134: skb_copy_bits(...)
 *   rxgk_verify_packet+0x2d3: rxgk_verify_mic_skb.constprop.0(...)
 *
 * On denial, skip the probed call instruction and make it look as though the
 * call returned -EACCES in %rax.  The kprobe program must then return 1 so
 * kprobe resumes at the modified instruction pointer.
 */
SEC("kprobe/rxgk_verify_packet+0x134")
int hook_rxgk_verify_packet_skb_copy_bits_call(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)BPF_CORE_READ(ctx, r13);

	if (inspect_skb_pages(skb, "rxgk_verify_packet+0x134") == NOACCESS_ERR)
		return deny_rxgk_call(ctx, "rxgk_verify_packet+0x134");

	return 0;
}

SEC("kprobe/rxgk_verify_packet+0x2d3")
int hook_rxgk_verify_packet_verify_mic_call(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)BPF_CORE_READ(ctx, r13);

	if (inspect_skb_pages(skb, "rxgk_verify_packet+0x2d3") == NOACCESS_ERR)
		return deny_rxgk_call(ctx, "rxgk_verify_packet+0x2d3");

	return 0;
}
