#ifndef PAGECACHE_INODE_UGO_BPF_H
#define PAGECACHE_INODE_UGO_BPF_H

/* Raw inode UGO policy, using current's subjective credentials. No ACL, LSM,
 * capability bypass, mount ID mapping or FD/VMA authorization is implied.
 * Callers must keep the inode alive and attribute asynchronous requests before
 * using current as their security subject. All failed reads deny access.
 * Include vmlinux.h, bpf_helpers.h and bpf_core_read.h before this file. */
#define UGO_MAY_READ 4U
#define UGO_MAY_WRITE 2U
#define UGO_MAY_EXEC 1U
#define UGO_EACCES (-13)
#define UGO_EFAULT (-14)
#define UGO_EINVAL (-22)
#define UGO_NGROUPS_MAX 65536

/* Linux sorts group_info->gid[] before publishing immutable credentials.
 * Binary search needs at most 17 comparisons for all 65536 supported groups;
 * this is not a limit to the first 17 supplementary groups. */
__noinline int inode_ugo_in_group(__u64 groups_address, __u32 gid)
{
    const struct group_info *groups = (void *)groups_address;
    int count;
    __u32 left = 0, right;

    if (!groups || BPF_CORE_READ_INTO(&count, groups, ngroups))
        return UGO_EFAULT;
    if (count < 0 || count > UGO_NGROUPS_MAX)
        return UGO_EINVAL;
    right = count;
#pragma clang loop unroll(disable)
    for (int i = 0; i < 17; i++) {
        __u32 mid, value;
        if (left >= right)
            return 0;
        mid = left + ((right - left) >> 1);
        if (BPF_CORE_READ_INTO(&value, groups, gid[mid].val))
            return UGO_EFAULT;
        if (gid == value)
            return 1;
        if (gid > value)
            left = mid + 1;
        else
            right = mid;
    }
    return left >= right ? 0 : UGO_EINVAL;
}

/* Global BPF subprograms avoid duplicating the permission search at each SG
 * call site. 0 = allowed; a negative errno = denied or unable to determine. */
__noinline int inode_ugo_check_address(__u64 inode_address, __u32 mask)
{
    const struct inode *inode = (void *)inode_address;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    const struct cred *cred;
    struct group_info *groups;
    __u32 owner, group, fsuid, fsgid, bits;
    umode_t mode;
    int member;

    if (!mask || (mask & ~7U))
        return UGO_EINVAL;
    if (!inode || !task || BPF_CORE_READ_INTO(&cred, task, cred) || !cred ||
        BPF_CORE_READ_INTO(&mode, inode, i_mode) ||
        BPF_CORE_READ_INTO(&owner, inode, i_uid.val) ||
        BPF_CORE_READ_INTO(&group, inode, i_gid.val) ||
        BPF_CORE_READ_INTO(&fsuid, cred, fsuid.val) ||
        BPF_CORE_READ_INTO(&fsgid, cred, fsgid.val))
        return UGO_EFAULT;

    if (fsuid == owner) {
        bits = mode >> 6;
    } else {
        member = fsgid == group;
        if (!member) {
            if (BPF_CORE_READ_INTO(&groups, cred, group_info))
                return UGO_EFAULT;
            member = inode_ugo_in_group((__u64)groups, group);
            if (member < 0)
                return member;
        }
        bits = member ? mode >> 3 : mode;
    }
    /* Owner/group denial never falls back to the more permissive other bits. */
    return (bits & mask) == mask ? 0 : UGO_EACCES;
}

/* A kprobe-derived address is an untrusted scalar, not a verifier-trusted
 * inode pointer. The subprogram only accesses it via checked probe reads. */
static __always_inline int inode_ugo_check(const struct inode *inode, __u32 mask)
{
    return inode_ugo_check_address((__u64)inode, mask);
}

#endif
