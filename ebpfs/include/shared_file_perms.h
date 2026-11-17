#ifndef PAGECACHE_SHARED_FILE_PERMS_H
#define PAGECACHE_SHARED_FILE_PERMS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include "file_perms.h"

/* Override only for isolated integration tests / separately built deployments. */
#ifndef FILE_PERMS_PIN_DIR
#define FILE_PERMS_PIN_DIR "/sys/fs/bpf/pagecache-write-v1"
#endif
#define FILE_PERMS_PIN_PATH FILE_PERMS_PIN_DIR "/" FILE_PERMS_MAP_NAME
#define WRITABLE_FDS_PIN_PATH FILE_PERMS_PIN_DIR "/" WRITABLE_FDS_MAP_NAME
#define WRITABLE_MAPS_PIN_PATH FILE_PERMS_PIN_DIR "/" WRITABLE_MAPS_MAP_NAME
#define AUTH_STATE_PIN_PATH FILE_PERMS_PIN_DIR "/" AUTH_STATE_MAP_NAME

/* Call before bpf_object__load(). Only common may create a missing map. */
static inline int shared_map_prepare(struct bpf_object *obj, const char *name,
                                     const char *path, bool owner, bool *needs_pin)
{
    struct bpf_map *map;
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    int fd, err;

    if (needs_pin)
        *needs_pin = false;

    map = bpf_object__find_map_by_name(obj, name);
    if (!map) {
        fprintf(stderr, "map not found: %s\n", name);
        return -ENOENT;
    }

    fd = bpf_obj_get(path);
    if (fd < 0) {
        err = -errno;
        if (err == -ENOENT && owner && needs_pin) {
            *needs_pin = true;
            return 0;
        }
        fprintf(stderr, "open shared map %s: %s; start common_hook first\n",
                path, strerror(-err));
        return err;
    }

    if (bpf_obj_get_info_by_fd(fd, &info, &info_len)) {
        err = -errno;
        fprintf(stderr, "read shared map info: %s\n", strerror(-err));
        goto out;
    }

    if (info.type != bpf_map__type(map) ||
        info.key_size != bpf_map__key_size(map) ||
        info.value_size != bpf_map__value_size(map) ||
        info.max_entries != bpf_map__max_entries(map) ||
        info.map_flags != bpf_map__map_flags(map)) {
        fprintf(stderr, "incompatible shared map at %s "
                "(type=%u key=%u value=%u entries=%u flags=%u); "
                "stop all loaders before replacing the pin\n",
                path, info.type, info.key_size,
                info.value_size, info.max_entries, info.map_flags);
        err = -EINVAL;
        goto out;
    }

    err = bpf_map__reuse_fd(map, fd);
    if (err)
        fprintf(stderr, "reuse shared map: %s\n", strerror(-err));
out:
    close(fd); /* libbpf duplicates the FD on successful reuse. */
    return err;
}

static inline int shared_file_perms_prepare(struct bpf_object *obj, bool owner,
                                           bool *needs_pin)
{
    int err = shared_map_prepare(obj, FILE_PERMS_MAP_NAME, FILE_PERMS_PIN_PATH,
                                 owner, needs_pin);
    if (!err && !owner)
        err = shared_map_prepare(obj, AUTH_STATE_MAP_NAME, AUTH_STATE_PIN_PATH,
                                 false, NULL);
    return err;
}

/* Publish only after common has successfully attached its recording hooks. */
static inline int shared_map_publish(struct bpf_object *obj, const char *name,
                                     const char *path)
{
    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, name);
    struct statfs fs;
    int err;

    if (!map)
        return -ENOENT;
    if (mkdir(FILE_PERMS_PIN_DIR, 0700) && errno != EEXIST) {
        err = -errno;
        fprintf(stderr, "create %s: %s; ensure bpffs is mounted\n",
                FILE_PERMS_PIN_DIR, strerror(-err));
        return err;
    }
    if (statfs(FILE_PERMS_PIN_DIR, &fs))
        return -errno;
    if (fs.f_type != BPF_FS_MAGIC) {
        fprintf(stderr, "%s must be on bpffs\n", FILE_PERMS_PIN_DIR);
        return -EINVAL;
    }

    err = bpf_map__pin(map, path);
    if (err)
        fprintf(stderr, "pin shared map %s: %s; "
                "run only one common_hook instance\n",
                path, strerror(-err));
    /* Never unlink/replace a concurrent owner's pin. */
    return err;
}

static inline int shared_file_perms_publish(struct bpf_object *obj)
{
    return shared_map_publish(obj, FILE_PERMS_MAP_NAME, FILE_PERMS_PIN_PATH);
}

static inline int shared_file_perms_report(struct bpf_object *obj)
{
    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, FILE_PERMS_MAP_NAME);
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);

    if (!map)
        return -ENOENT;
    if (bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &info_len))
        return -errno;
    printf("shared map: %s id=%u\n", FILE_PERMS_PIN_PATH, info.id);
    fflush(stdout);
    return 0;
}

#endif
