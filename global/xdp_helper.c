#ifndef __COMMON_XDP_HELPER_H
#define __COMMON_XDP_HELPER_H

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

#include "common_define.h"

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
    // struct bpf_prog_load_attr prog_load_attr = {
    //     .prog_type = BPF_PROG_TYPE_XDP,
    //     .ifindex = ifidx,
    // };
    // prog_load_attr.file = filename;

    // printf("bpf ifidx: %d\n", ifidx);

    // int err = bpf_prog_load_xattr(
    //     &prog_load_attr,
    //     &bpf_obj,
    //     &first_prog_fd);

    int first_prog_fd = -1;
    struct bpf_object *bpf_obj;
    int err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &bpf_obj, &first_prog_fd);
    if (err < 0)
    {
        fprintf(stderr, "ERR: load XDP prog from obj file(%s) failed: err(%d): %s\n", filename, -err, strerror(-err));
        return NULL;
    }

    return bpf_obj;
}

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
    int offload_ifidx = 0;
    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
    {
        offload_ifidx = cfg->netif_idx;
    }

    struct bpf_object *bpf_obj = load_bpf_obj_file(cfg->obj_filename, offload_ifidx);
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

    strncpy(cfg->progsec, bpf_program__section_name(bpf_prog), sizeof(cfg->progsec));

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

#define XDP_UNKNOWN XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX XDP_UNKNOWN + 1
#endif

#endif