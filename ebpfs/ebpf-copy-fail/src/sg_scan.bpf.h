#ifndef COPY_FAIL_SG_SCAN_BPF_H
#define COPY_FAIL_SG_SCAN_BPF_H

/* Each traversal has one budget covering all SG nodes and covered pages.
 * Legacy tests also exercise TX list traversal; active guards scan destinations. */
#define COPY_FAIL_SCAN_LIMIT 1000000U
#define CF_PAGE_SIZE 4096ULL
#define CF_SG_CHAIN 1UL
#define CF_SG_END 2UL
#define CF_MAPPING_FLAGS 3UL
#define CF_DENY (-13)

extern bool CONFIG_SPARSEMEM_VMEMMAP __kconfig;
extern bool CONFIG_PAGE_SIZE_4KB __kconfig;

/* Partial CO-RE views: AF_ALG lives in module BTF, not our base vmlinux.h. */
struct af_alg_sgl___cf { struct sg_table sgt; } __attribute__((preserve_access_index));
struct af_alg_rsgl___cf { struct af_alg_sgl___cf sgl; } __attribute__((preserve_access_index));
struct af_alg_async_req___cf {
    struct af_alg_rsgl___cf first_rsgl;
    struct af_alg_rsgl___cf *last_rsgl;
} __attribute__((preserve_access_index));
struct af_alg_ctx___cf { struct list_head tsgl_list; } __attribute__((preserve_access_index));
struct af_alg_tsgl___cf {
    struct list_head list;
    unsigned int cur;
    struct scatterlist sg[];
} __attribute__((preserve_access_index));
enum pagetype___cf {
    PGTY_buddy = 0xf0, PGTY_offline = 0xf1, PGTY_table = 0xf2,
    PGTY_guard = 0xf3, PGTY_hugetlb = 0xf4, PGTY_slab = 0xf5,
    PGTY_zsmalloc = 0xf6, PGTY_unaccepted = 0xf7, PGTY_large_kmalloc = 0xf8,
};

enum cf_phase { CF_RX_SG, CF_TX_NODE, CF_TX_SG, CF_PAGE, CF_DONE };
enum cf_error { CF_OK, CF_READ_ERROR, CF_UNAUTHORIZED, CF_BAD_STRUCTURE,
                CF_BUDGET_EXHAUSTED, CF_UNSUPPORTED_LAYOUT, CF_LOOP_ERROR };
struct cf_scan {
    struct scatterlist *sg;
    struct list_head *tx_head, *tx_node, *tx_next, *tx_prev;
    struct page *page;
    __u64 page_stride, sg_stride, pages_left;
    __u32 tgid, tx_left, phase, error;
    __u32 steps, pages_checked, sg_checked, tx_nodes;
    bool rx, last, complete;
};

static __always_inline long cf_fail(struct cf_scan *s, __u32 error)
{
    s->error = error;
    return 1; /* Callback stop, NOT permission to proceed. */
}
static __always_inline int cf_start_tx(struct cf_scan *s)
{
    if (!s->tx_head || s->tx_node == s->tx_head) {
        s->phase = CF_DONE;
        s->complete = true;
        return 1;
    }
    if (!s->tx_node) return cf_fail(s, CF_BAD_STRUCTURE);
    s->phase = CF_TX_NODE;
    return 0;
}
static __always_inline int cf_finish_sg(struct cf_scan *s)
{
    if (s->rx) {
        if (s->last) return cf_start_tx(s);
        s->phase = CF_RX_SG;
    } else {
        if (!s->tx_left) return cf_fail(s, CF_BAD_STRUCTURE);
        if (--s->tx_left == 0) {
            s->tx_prev = s->tx_node;
            s->tx_node = s->tx_next;
            return cf_start_tx(s);
        }
        s->phase = CF_TX_SG;
    }
    if ((__u64)s->sg > ~0ULL - s->sg_stride)
        return cf_fail(s, CF_BAD_STRUCTURE);
    s->sg = (void *)((__u64)s->sg + s->sg_stride);
    return 0;
}

/* Resolve tail pages and HVO fake heads before reading file ownership. Never
 * use a tail's mapping field as if it were the head folio's mapping. */
/* A global subprogram is verified once, rather than multiplying all page-read
 * branches by every possible state of the traversal callback. */
__noinline int cf_check_page(struct cf_scan *s)
{
    if (!s) return CF_BAD_STRUCTURE;
    struct page *page = s->page;
    struct address_space *mapping;
    struct inode *inode;
    struct super_block *sb;
    unsigned long head, flags, mapping_raw;
    __u32 page_type;

    if (!page) return CF_BAD_STRUCTURE;
    if (BPF_CORE_READ_INTO(&head, page, compound_head)) return CF_READ_ERROR;
    if (head & 1) {
        page = (void *)(head - 1);
        if (!page || ((__u64)page & 7)) return CF_BAD_STRUCTURE;
    } else {
        if (BPF_CORE_READ_INTO(&flags, page, flags)) return CF_READ_ERROR;
        if (!((__u64)page & (CF_PAGE_SIZE - 1)) &&
            (flags & (1UL << bpf_core_enum_value(enum pageflags, PG_head)))) {
            if ((__u64)page > ~0ULL - s->page_stride) return CF_BAD_STRUCTURE;
            struct page *next = (void *)((__u64)page + s->page_stride);
            if (BPF_CORE_READ_INTO(&head, next, compound_head)) return CF_READ_ERROR;
            if (head & 1) {
                page = (void *)(head - 1);
                if (!page || ((__u64)page & 7)) return CF_BAD_STRUCTURE;
            }
        }
    }
    if (BPF_CORE_READ_INTO(&page_type, page, page_type)) return CF_READ_ERROR;
    page_type >>= 24;
    if (page_type == bpf_core_enum_value(enum pagetype___cf, PGTY_slab) ||
        page_type == bpf_core_enum_value(enum pagetype___cf, PGTY_large_kmalloc))
        return CF_OK; /* Kernel buffers, not file page cache. */
    if (page_type >= 0xf0 && page_type != 0xff &&
        page_type != bpf_core_enum_value(enum pagetype___cf, PGTY_hugetlb))
        return CF_BAD_STRUCTURE;
    if (BPF_CORE_READ_INTO(&mapping_raw, page, mapping)) return CF_READ_ERROR;
    if (!mapping_raw || (mapping_raw & CF_MAPPING_FLAGS))
        return CF_OK; /* Unmapped allocation or anonymous/KSM folio. */
    mapping = (void *)mapping_raw;
    if (BPF_CORE_READ_INTO(&inode, mapping, host)) return CF_READ_ERROR;
    if (!inode) return CF_BAD_STRUCTURE;
    if (BPF_CORE_READ_INTO(&sb, inode, i_sb)) return CF_READ_ERROR;
    if (!sb) return CF_BAD_STRUCTURE;
    int rc = inode_ugo_check(inode, UGO_MAY_WRITE);
    if (!rc) return CF_OK;
    return rc == UGO_EACCES ? CF_UNAUTHORIZED : CF_READ_ERROR;
}

/* One callback handles at most one list/chain node, one SG descriptor, or one
 * base page. There is no inner traversal loop and empty/cyclic lists cost budget. */
static long cf_scan_step(__u32 index, void *data)
{
    struct cf_scan *s = data;
    s->steps++;
    if (s->error || s->complete) return 1;
    if (s->phase == CF_PAGE) {
        int error = cf_check_page(s);
        s->pages_checked++;
        if (error) return cf_fail(s, error);
        if (--s->pages_left == 0) return cf_finish_sg(s);
        if ((__u64)s->page > ~0ULL - s->page_stride)
            return cf_fail(s, CF_BAD_STRUCTURE);
        s->page = (void *)((__u64)s->page + s->page_stride);
        return 0;
    }
    if (s->phase == CF_TX_NODE) {
        struct af_alg_tsgl___cf *node;
        struct list_head *list = s->tx_node;
        struct list_head *prev;
        __u32 cur;
        __u64 list_off = bpf_core_field_offset(struct af_alg_tsgl___cf, list);
        __u64 sg_off = bpf_core_field_offset(struct af_alg_tsgl___cf, sg);
        __u64 node_size = bpf_core_type_size(struct af_alg_tsgl___cf);
        if (!s->tx_node || (__u64)s->tx_node < list_off || node_size >= CF_PAGE_SIZE)
            return cf_fail(s, CF_BAD_STRUCTURE);
        node = (void *)((__u64)s->tx_node - list_off);
        if (BPF_CORE_READ_INTO(&prev, list, prev) ||
            BPF_CORE_READ_INTO(&s->tx_next, list, next) ||
            BPF_CORE_READ_INTO(&cur, node, cur)) return cf_fail(s, CF_READ_ERROR);
        if (prev != s->tx_prev || !s->tx_next || s->tx_next == s->tx_node)
            return cf_fail(s, CF_BAD_STRUCTURE);
        /* Kernel AF_ALG allocation reserves one slot for a chain marker. */
        if (cur > (CF_PAGE_SIZE - node_size) / s->sg_stride - 1)
            return cf_fail(s, CF_BAD_STRUCTURE);
        s->tx_nodes++;
        if (!cur) {
            s->tx_prev = s->tx_node;
            s->tx_node = s->tx_next;
            return cf_start_tx(s);
        }
        if ((__u64)node > ~0ULL - sg_off) return cf_fail(s, CF_BAD_STRUCTURE);
        s->sg = (void *)((__u64)node + sg_off);
        s->tx_left = cur;
        s->phase = CF_TX_SG;
        return 0;
    }
    if (s->phase == CF_RX_SG || s->phase == CF_TX_SG) {
        unsigned long link;
        __u32 offset, length;
        __u64 base, delta, span;
        struct scatterlist *sg = s->sg;
        if (!sg) return cf_fail(s, CF_BAD_STRUCTURE);
        if (BPF_CORE_READ_INTO(&link, sg, page_link) ||
            BPF_CORE_READ_INTO(&offset, sg, offset) ||
            BPF_CORE_READ_INTO(&length, sg, length)) return cf_fail(s, CF_READ_ERROR);
        if (link & CF_SG_CHAIN) {
            if (s->phase != CF_RX_SG || (link & CF_SG_END) || offset || length)
                return cf_fail(s, CF_BAD_STRUCTURE);
            s->sg = (void *)(link & ~(CF_SG_CHAIN | CF_SG_END));
            if (!s->sg) return cf_fail(s, CF_BAD_STRUCTURE);
            return 0;
        }
        s->rx = s->phase == CF_RX_SG;
        s->last = !!(link & CF_SG_END);
        s->sg_checked++;
        if (!length) return cf_finish_sg(s); /* Consumed TX slots can have no page. */
        base = link & ~(CF_SG_CHAIN | CF_SG_END);
        if (!base) return cf_fail(s, CF_BAD_STRUCTURE);
        delta = ((__u64)offset / CF_PAGE_SIZE) * s->page_stride;
        if (base > ~0ULL - delta) return cf_fail(s, CF_BAD_STRUCTURE);
        s->page = (void *)(base + delta);
        span = (__u64)(offset % CF_PAGE_SIZE) + length;
        s->pages_left = (span + CF_PAGE_SIZE - 1) / CF_PAGE_SIZE;
        s->phase = CF_PAGE;
        return 0;
    }
    return cf_fail(s, CF_BAD_STRUCTURE);
}

static __always_inline int cf_scan_init(struct cf_scan *s, struct scatterlist *rx,
                                         struct list_head *tx_head)
{
    s->tgid = bpf_get_current_pid_tgid() >> 32;
    s->page_stride = bpf_core_type_size(struct page);
    s->sg_stride = bpf_core_type_size(struct scatterlist);
    s->sg = rx;
    s->tx_head = tx_head;
    s->tx_prev = tx_head;
    if (!CONFIG_SPARSEMEM_VMEMMAP || !CONFIG_PAGE_SIZE_4KB ||
        !s->page_stride || !s->sg_stride) {
        s->error = CF_UNSUPPORTED_LAYOUT;
        return CF_DENY;
    }
    if (tx_head && BPF_CORE_READ_INTO(&s->tx_node, tx_head, next)) {
        s->error = CF_READ_ERROR;
        return CF_DENY;
    }
    if (tx_head && !s->tx_node) {
        s->error = CF_BAD_STRUCTURE;
        return CF_DENY;
    }
    if (rx) s->phase = CF_RX_SG;
    else cf_start_tx(s);
    return s->error ? CF_DENY : 0;
}
static __always_inline int cf_scan_run(struct cf_scan *s, __u32 budget)
{
    long ret;
    if (s->error) return CF_DENY;
    if (s->complete) return 0;
    if (budget > COPY_FAIL_SCAN_LIMIT) {
        s->error = CF_BAD_STRUCTURE;
        return CF_DENY;
    }
    ret = bpf_loop(budget, cf_scan_step, s, 0);
    if (ret < 0 && !s->error) s->error = CF_LOOP_ERROR;
    if (!s->error && !s->complete) s->error = CF_BUDGET_EXHAUSTED;
    return s->error ? CF_DENY : 0;
}
/* The AEAD destination may include TX pages linked after RX extraction.
 * req->src and the socket's unconsumed TX list are not write targets merely
 * because the crypto operation reads them. We conservatively authorize the
 * complete destination chain, including the aliased tag buffer. */
static __always_inline int cf_scan_aead_dst(struct cf_scan *s,
                                           struct aead_request *req,
                                           __u32 budget)
{
    struct scatterlist *dst = NULL;
    __u32 assoclen, cryptlen;
    if (!req) {
        s->error = CF_BAD_STRUCTURE;
        return CF_DENY;
    }
    if (BPF_CORE_READ_INTO(&dst, req, dst) ||
        BPF_CORE_READ_INTO(&assoclen, req, assoclen) ||
        BPF_CORE_READ_INTO(&cryptlen, req, cryptlen)) {
        s->error = CF_READ_ERROR;
        return CF_DENY;
    }
    if (!dst && (assoclen || cryptlen)) {
        s->error = CF_BAD_STRUCTURE;
        return CF_DENY;
    }
    if (cf_scan_init(s, dst, NULL)) return CF_DENY;
    return cf_scan_run(s, budget);
}
#endif
