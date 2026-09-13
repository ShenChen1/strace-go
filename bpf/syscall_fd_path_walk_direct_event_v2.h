#ifndef STRACE_GO_SYSCALL_FD_PATH_WALK_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_PATH_WALK_DIRECT_EVENT_V2_H

static __always_inline struct fd_path_scratch *lookup_fd_path_scratch(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&fd_path_scratch_map, &key);
}

static __always_inline s32 append_dentry_name_direct(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 *path_len,
    struct dentry *dentry,
    struct fd_path_scratch *scratch)
{
    struct qstr name = {};
    if (BPF_CORE_READ_INTO(&name, dentry, d_name) < 0 || !name.name) {
        return FD_PATH_PROBE_PATH_FAILED;
    }
    u32 name_len = name.len;
    if (name_len == 0 || name_len > 255 || *path_len > 255) {
        return FD_PATH_PROBE_PATH_FAILED;
    }

    char slash = '/';
    if (bpf_dynptr_write(ptr, data_offset + *path_len, &slash, sizeof(slash), 0) < 0) {
        record_ringbuf_copy_fail();
        return FD_PATH_PROBE_PATH_FAILED;
    }
    (*path_len)++;
    if (bpf_probe_read_kernel(scratch->name, name_len, name.name) < 0) {
        return FD_PATH_PROBE_PATH_FAILED;
    }
    if (bpf_dynptr_write(
            ptr,
            data_offset + *path_len,
            scratch->name,
            name_len,
            0) < 0) {
        record_ringbuf_copy_fail();
        return FD_PATH_PROBE_PATH_FAILED;
    }
    *path_len += name_len;
    return 0;
}

static __always_inline void store_dentry_component(
    u64 components[FD_PATH_DENTRY_MAX],
    u32 index,
    struct dentry *dentry)
{
    switch (index) {
    case 0:
        components[0] = (u64)dentry;
        break;
    case 1:
        components[1] = (u64)dentry;
        break;
    case 2:
        components[2] = (u64)dentry;
        break;
    case 3:
        components[3] = (u64)dentry;
        break;
    case 4:
        components[4] = (u64)dentry;
        break;
    case 5:
        components[5] = (u64)dentry;
        break;
    case 6:
        components[6] = (u64)dentry;
        break;
    case 7:
        components[7] = (u64)dentry;
        break;
    default:
        break;
    }
}

static __always_inline struct dentry *load_dentry_component(
    u64 components[FD_PATH_DENTRY_MAX],
    u32 index)
{
    switch (index) {
    case 0:
        return (struct dentry *)components[0];
    case 1:
        return (struct dentry *)components[1];
    case 2:
        return (struct dentry *)components[2];
    case 3:
        return (struct dentry *)components[3];
    case 4:
        return (struct dentry *)components[4];
    case 5:
        return (struct dentry *)components[5];
    case 6:
        return (struct dentry *)components[6];
    case 7:
        return (struct dentry *)components[7];
    default:
        return 0;
    }
}

static __always_inline struct mount *fd_path_mount_from_vfsmount_direct(
    struct vfsmount *mnt)
{
    if (!mnt) {
        return 0;
    }
    return (struct mount *)((char *)mnt - bpf_core_field_offset(struct mount, mnt));
}

static __always_inline struct vfsmount *fd_path_vfsmount_from_mount_direct(
    struct mount *mount)
{
    if (!mount) {
        return 0;
    }
    return (struct vfsmount *)((char *)mount + bpf_core_field_offset(struct mount, mnt));
}

static __always_inline s32 read_dentry_path_direct(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    struct path *path)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return FD_PATH_PROBE_PATH_FAILED;
    }
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *mnt = BPF_CORE_READ(path, mnt);
    struct dentry *root = mnt ? BPF_CORE_READ(mnt, mnt_root) : 0;
    u32 component_count = 0;
    u32 reached_root = 0;

#pragma clang loop unroll(disable)
    for (u32 i = 0; i < FD_PATH_DENTRY_MAX; i++) {
        if (!dentry) {
            break;
        }
        if (dentry == root) {
            struct mount *mount = fd_path_mount_from_vfsmount_direct(mnt);
            struct mount *parent_mount = mount ? BPF_CORE_READ(mount, mnt_parent) : 0;
            if (!parent_mount || parent_mount == mount) {
                reached_root = 1;
                break;
            }
            dentry = mount ? BPF_CORE_READ(mount, mnt_mountpoint) : 0;
            mnt = fd_path_vfsmount_from_mount_direct(parent_mount);
            root = mnt ? BPF_CORE_READ(mnt, mnt_root) : 0;
            continue;
        }
        if (component_count >= FD_PATH_DENTRY_MAX) {
            break;
        }
        store_dentry_component(scratch->components, component_count, dentry);
        component_count++;
        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (!parent || parent == dentry) {
            break;
        }
        dentry = parent;
    }
    if (!reached_root) {
        return FD_PATH_PROBE_PATH_FAILED;
    }

    u32 path_len = 0;
#pragma clang loop unroll(disable)
    for (u32 i = 0; i < FD_PATH_DENTRY_MAX; i++) {
        if (i >= component_count) {
            break;
        }
        struct dentry *component = load_dentry_component(scratch->components, component_count - i - 1);
        if (append_dentry_name_direct(ptr, data_offset, &path_len, component, scratch) < 0) {
            return FD_PATH_PROBE_PATH_FAILED;
        }
    }

    if (path_len == 0) {
        char slash = '/';
        if (bpf_dynptr_write(ptr, data_offset, &slash, sizeof(slash), 0) < 0) {
            record_ringbuf_copy_fail();
            return FD_PATH_PROBE_PATH_FAILED;
        }
        path_len = 1;
    }
    char terminator = 0;
    if (bpf_dynptr_write(ptr, data_offset + path_len, &terminator, sizeof(terminator), 0) < 0) {
        record_ringbuf_copy_fail();
        return FD_PATH_PROBE_PATH_FAILED;
    }
    return (s32)path_len + 1;
}

#endif
