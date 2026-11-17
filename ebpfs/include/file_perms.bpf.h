#ifndef PAGECACHE_FILE_PERMS_BPF_H
#define PAGECACHE_FILE_PERMS_BPF_H
#include "file_perms.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILE_PERMS);
    __type(key, struct file_perm_key);
    __type(value, file_write_refs);
} file_write_perms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILE_PERMS);
    __type(key, __u32);
    __type(value, struct file_auth_state);
} auth_state SEC(".maps");

static __always_inline file_write_refs file_write_count(const struct file_perm_key *key)
{
    file_write_refs *refs = bpf_map_lookup_elem(&file_write_perms, key);
    return refs ? *(volatile file_write_refs *)refs : 0;
}

static __always_inline bool file_write_allowed(const struct file_perm_key *key)
{
    struct file_auth_state *s = bpf_map_lookup_elem(&auth_state, &key->tgid);
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    if (!s || s->errors || s->rebuilding || s->vma_active || s->exec_active ||
        s->vma_epoch != s->vma_seen)
        return false;
    if (s->files_id != (__u64)BPF_CORE_READ(task, files) ||
        s->mm_id != (__u64)BPF_CORE_READ(task, mm))
        return false;
    return file_write_count(key) > 0;
}

static __always_inline int file_write_get(const struct file_perm_key *key)
{
    file_write_refs zero = 0;
    file_write_refs *refs = bpf_map_lookup_elem(&file_write_perms, key);
    if (!refs) {
        long err = bpf_map_update_elem(&file_write_perms, key, &zero, BPF_NOEXIST);
        if (err && err != -17)
            return err;
        refs = bpf_map_lookup_elem(&file_write_perms, key);
        if (!refs)
            return -2;
    }
    __sync_fetch_and_add(refs, 1);
    return 0;
}

/* Only the winner of deleting a detail entry releases its contribution. */
static __always_inline int file_write_put(const struct file_perm_key *key)
{
    file_write_refs *refs = bpf_map_lookup_elem(&file_write_perms, key);
    if (!refs)
        return -2;
    for (int i = 0; i < 32; i++) {
        file_write_refs old = *(volatile file_write_refs *)refs;
        if (!old)
            return -22;
        if (__sync_val_compare_and_swap(refs, old, old - 1) == old)
            return 0;
    }
    return -11;
}
#endif
