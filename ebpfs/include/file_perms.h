#ifndef PAGECACHE_FILE_PERMS_H
#define PAGECACHE_FILE_PERMS_H

#define MAX_FILE_PERMS 65536
#define FILE_PERMS_MAP_NAME "file_write_perms"
#define WRITABLE_FDS_MAP_NAME "writable_fds"
#define WRITABLE_MAPS_MAP_NAME "writable_maps"
#define AUTH_STATE_MAP_NAME "auth_state"

struct file_perm_key {
    __u32 tgid;
    __u32 dev;
    __u64 ino;
};
struct file_fd_key { __u32 tgid; __u32 fd; };
struct file_identity { __u32 dev; __u32 pad; __u64 ino; };
struct file_map_key { __u64 map_id; __u32 tgid; __u32 pad; };
typedef __u64 file_write_refs;

/* Shared with consumers: a partially rebuilt/failed record never authorizes. */
struct file_auth_state {
    __u64 files_id;
    __u64 mm_id;
    __u64 vma_epoch;
    __u64 vma_seen;
    __u32 vma_active;
    __u32 exec_active;
    __u32 rebuilding;
    __u32 errors;
};
#define AUTH_FD_ERROR 1U
#define AUTH_VMA_ERROR 2U
#define AUTH_UNSUPPORTED 4U

_Static_assert(sizeof(struct file_perm_key) == 16, "count key ABI");
_Static_assert(sizeof(struct file_fd_key) == 8, "FD key ABI");
_Static_assert(sizeof(struct file_identity) == 16, "file identity ABI");
_Static_assert(sizeof(struct file_map_key) == 16, "mapping key ABI");
_Static_assert(sizeof(struct file_auth_state) == 48, "state ABI");
#endif
