#ifndef PAGECACHE_SKB_FRAG_BPF_H
#define PAGECACHE_SKB_FRAG_BPF_H

/* Linux 6.17 skb fragments use netmem/len/offset, not bio_vec fields.
 * Partial CO-RE view avoids relying on the stale typedef in local vmlinux.h. */
struct skb_frag___pagecache {
    unsigned long netmem;
    unsigned int len;
    unsigned int offset;
} __attribute__((preserve_access_index));

static __always_inline struct skb_frag___pagecache *
pagecache_skb_frag(struct skb_shared_info *shinfo, __u32 index)
{
    return (void *)((unsigned long)shinfo +
                   bpf_core_field_offset(struct skb_shared_info, frags) +
                   index * bpf_core_type_size(struct skb_frag___pagecache));
}

static __always_inline int
pagecache_skb_frag_page(const struct skb_frag___pagecache *frag, struct page **page)
{
    unsigned long netmem;
    if (BPF_CORE_READ_INTO(&netmem, frag, netmem) || !netmem || (netmem & 1))
        return -1; /* Unreadable or NET_IOV; never interpret net_iov as page. */
    *page = (void *)netmem;
    return 0;
}

#endif
