#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include <linux/types.h>
#include <linux/if_link.h>

#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../global/err.h"
#include "common_define.h"
#include "xdp_helper.h"

int xdp_link_attach(int ifidx, __u32 xdp_flags, int prog_fd)
{
    int err = bpf_set_link_xdp_fd(ifidx, prog_fd, xdp_flags);
    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        __u32 old_flags = xdp_flags;
        xdp_flags &= ~XDP_FLAGS_MODES;
        xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        if (!(err = bpf_set_link_xdp_fd(ifidx, -1, xdp_flags)))
        {
            err = bpf_set_link_xdp_fd(ifidx, prog_fd, old_flags);
        }
    }

    if (err < 0)
    {
        fprintf(stderr, "ifidx(%d) link set xdp fd failed (%d): %s\n", ifidx, -err, strerror(-err));
        switch (-err)
        {
        case EBUSY:
        case EEXIST:
            fprintf(stderr, "Hint: XDP already loaded\nÏ");
            break;
        case EOPNOTSUPP:
            fprintf(stderr, "Hint: Native-XDP not supported");
            break;
        default:
            break;
        }
        return EXIT_FAIL_XDP;
    }
    return EXIT_OK;
}

int xdp_link_detach(int ifidx, __u32 xdp_flags, __u32 target_prog_id)
{
    __u32 curr_prog_id;
    int err = bpf_get_link_xdp_id(ifidx, &curr_prog_id, xdp_flags);
    if (err < 0)
    {
        fprintf(stderr, "ERR: get link xdp id failed err(%d): %s\n", -err, strerror(-err));
        return EXIT_FAIL_XDP;
    }

    if (!curr_prog_id)
    {
        printf("INFO: %s() no curr XDP prog on ifidx: %d\n", __func__, ifidx);
        return EXIT_OK;
    }

    if (target_prog_id && curr_prog_id != target_prog_id)
    {
        fprintf(stderr, "ERR: %s() target prog ID(%d) not match(%d), not removing\n", __func__, target_prog_id, curr_prog_id);
        return EXIT_FAIL;
    }

    if ((err = bpf_set_link_xdp_fd(ifidx, -1, xdp_flags)) < 0)
    {
        fprintf(stderr, "ERR: %s() detach xdp failed: err(%d) %s\n", __func__, -err, strerror(-err));
        return EXIT_FAIL_XDP;
    }

    printf("INFO: %s() rm XDP prog ID: %d on ifidx: %d\n", __func__, curr_prog_id, ifidx);
    return EXIT_OK;
}

struct bpf_object *load_bpf_obj_file(const char *filename, int ifidx)
{
    int first_prog_fd = -1;
    struct bpf_object *bpf_obj;
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex = ifidx,
    };
    prog_load_attr.file = filename;

    printf("bpf ifidx: %d\n", ifidx);

    int err = bpf_prog_load_xattr(
        &prog_load_attr,
        &bpf_obj,
        &first_prog_fd);
    if (err < 0)
    {
        fprintf(stderr, "ERR: load XDP prog from obj file(%s) failed: err(%d): %s\n", filename, -err, strerror(-err));
        return NULL;
    }

    return bpf_obj;
}

struct bpf_object *open_bpf_obj(const char *filename, int ifidx)
{
    struct bpf_object_open_attr open_attr = {
        .file = filename,
        .prog_type = BPF_PROG_TYPE_XDP,
    };

    struct bpf_object *obj = bpf_object__open_xattr(&open_attr);
    if (IS_ERR_OR_NULL(obj))
    {
        int err = -PTR_ERR(obj);
        fprintf(stderr, "ERR: open BPF-OBJ file(%s) (%d): %s\n",
                filename,
                err,
                strerror(err));
        return NULL;
    }

    struct bpf_program *prog, *first_prog = NULL;
    bpf_object__for_each_program(prog, obj)
    {
        bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
        bpf_program__set_ifindex(prog, ifidx);
        if (!first_prog)
        {
            first_prog = prog;
            break;
        }
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj)
    {
        if (!bpf_map__is_offload_neutral(map))
        {
            bpf_map__set_ifindex(map, ifidx);
        }
    }

    if (!first_prog)
    {
        fprintf(stderr, "ERR: file(%s) program not found\n", filename);
        return NULL;
    }

    return obj;
}

int reuse_maps(struct bpf_object *obj, const char *path)
{
    if (!obj)
    {
        return -ENOENT;
    }

    if (!path)
    {
        return -EINVAL;
    }

    char buf[PATH_MAX];
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj)
    {
        int len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
        if (len < 0)
        {
            return -EINVAL;
        }
        else if (len >= PATH_MAX)
        {
            return -ENAMETOOLONG;
        }

        int pinned_map_fd = bpf_obj_get(buf);
        if (pinned_map_fd < 0)
        {
            return pinned_map_fd;
        }

        int err = bpf_map__reuse_fd(map, pinned_map_fd);
        if (err)
        {
            return err;
        }
    }

    return 0;
}

struct bpf_object *load_bpf_obj_file_reuse_maps(
    const char *filename,
    int ifidx,
    const char *pin_dir)
{
    struct bpf_object *obj = open_bpf_obj(filename, ifidx);
    if (!obj)
    {
        fprintf(stderr, "ERR: open file(%s) failed\n", filename);
        return NULL;
    }

    int err = reuse_maps(obj, pin_dir);
    if (err)
    {
        fprintf(stderr, "ERR: reuse map in file(%s) pin_dir(%s) failed(%d): %s\n", filename, pin_dir, err, strerror(-err));
        return NULL;
    }

    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "ERR: load BPF-OBJ file(%s) failed(%d): %s\n", filename, err, strerror(-err));
        return NULL;
    }

    return obj;
}

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
    int offload_ifidx = 0;
    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
    {
        offload_ifidx = cfg->netif_idx;
    }

    struct bpf_object *bpf_obj;
    if (cfg->reuse_maps)
    {
        bpf_obj = load_bpf_obj_file_reuse_maps(
            cfg->obj_filename,
            offload_ifidx,
            cfg->pin_dir);
    }
    else
    {
        bpf_obj = load_bpf_obj_file(
            cfg->obj_filename,
            offload_ifidx);
    }

    if (!bpf_obj)
    {
        fprintf(stderr, "ERR: loading file failed: %s\n", cfg->obj_filename);
        exit(EXIT_FAIL_BPF);
    }

    struct bpf_program *bpf_prog;
    if (cfg->progsec[0])
    {
        bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
    }
    else
    {
        bpf_prog = bpf_program__next(NULL, bpf_obj);
    }

    if (!bpf_prog)
    {
        fprintf(stderr, "ERR: load BPF-prog from file(%s) failed\n", cfg->obj_filename);
        exit(EXIT_FAIL_BPF);
    }

    strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

    int prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0)
    {
        fprintf(stderr, "ERR: bpf_program__fd failed, result(%d)\n", prog_fd);
        exit(EXIT_FAIL_BPF);
    }

    int err = xdp_link_attach(cfg->netif_idx, cfg->xdp_flags, prog_fd);
    if (err)
    {
        exit(err);
    }
    return bpf_obj;
}

static const char *xdp_act_names[XDP_ACTION_MAX] = {
    [XDP_ABORTED] = "XDP_ABORTED",
    [XDP_DROP] = "XDP_DROP",
    [XDP_PASS] = "XDP_PASS",
    [XDP_TX] = "XDP_TX",
    [XDP_REDIRECT] = "XDP_REDIRECT",
    [XDP_UNKNOWN] = "XDP_UNKNOWN",
};

const char *action2str(__u32 act)
{
    if (act < XDP_ACTION_MAX)
    {
        return xdp_act_names[act];
    }
    return NULL;
}

int open_bpf_map_file(const struct config *cfg, struct bpf_map_info *info)
{
    char filename[PATH_MAX];

    int len = snprintf(filename, PATH_MAX, "%s/%s/%s", cfg->pin_basedir, cfg->netif_name, cfg->mapname);
    if (len < 0)
    {
        fprintf(stderr, "ERR: format map file name failed(%d): %s\n", len, strerror(-len));
        return -len;
    }

    printf("INFO: map filename: %s\n", cfg->mapname);

    int fd = bpf_obj_get(filename);
    if (fd < 0)
    {
        fprintf(stderr, "ERR: get bpf map failed(%d): %s\n", fd, strerror(-fd));
        return fd;
    }

    if (info)
    {
        __u32 info_len = sizeof(*info);
        int err = bpf_obj_get_info_by_fd(fd, info, &info_len);
        if (err)
        {
            fprintf(stderr, "ERR: get info failed(%d): %s\n", err, strerror(-err));
            return EXIT_FAIL_BPF;
        }
    }
    return fd;
}