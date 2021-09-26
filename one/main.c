#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "../global/common_define.h"
#include "../global/cmd_args.h"
#include "../global/xdp_helper.h"
#include "kern_obj.h"

static const char *default_bpf_obj_filename = "xdp_prog_kern.o";
static const char *default_pin_basedir = "/sys/fs/bpf";
static const char *default_map_name = "xdp_stat_map";

struct option_wrapper wrappers[] = {
    {{"dev", required_argument, NULL, 'd'}, "device name", .required = true},
    {{"unload", no_argument, NULL, 'U'}, "unload or not"},
    {{"skb-mode", no_argument, NULL, 'S'}, "skb-mode"},
    {{"progsec", required_argument, NULL, 1}, "progsec", "haha"},
    {{"filename", required_argument, NULL, 2}, "filename", "<file>"},
    {{"pin_basedir", required_argument, NULL, 3}, "pin_basedir", "<pin_basedir>"},
    {{"mapname", required_argument, NULL, 4}, "mapname", "<mapname>"},
};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_name *map;
    map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (map)
    {
        fprintf(stderr, "ERR: find map by name failed(%d): %s\n", map, mapname);
        return -1;
    }

    return bpf_map__fd(map);
}

int check_map_fd_info(int map_fd, struct bpf_map_info *info, struct bpf_map_info *exp)
{
    return 0;
}

int main(int argc, char *argv[])
{
    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .netif_idx = -1,
        .do_unload = false,
    };

    strncpy(cfg.obj_filename, default_bpf_obj_filename, sizeof(cfg.obj_filename));
    strncpy(cfg.pin_basedir, default_pin_basedir, sizeof(cfg.pin_basedir));
    strncpy(cfg.mapname, default_map_name, sizeof(cfg.mapname));

    parse_cmd_args(
        argc,
        argv,
        wrappers,
        &cfg);

    if (cfg.netif_idx == -1)
    {
        fprintf(stderr, "ERR: required option --dev missing\n\n");
        return EXIT_ACQUIRE_OPT_FAIL;
    }
    if (cfg.do_unload)
    {
        return xdp_link_detach(cfg.netif_idx, cfg.xdp_flags, 0);
    }

    struct bpf_object *bpf_obj = load_bpf_and_xdp_attach(&cfg);
    if (!bpf_obj)
    {
        return EXIT_FAIL_BPF;
    }

    printf("Success: Loaded BPF-obj(%s), used section(%s)\n", cfg.obj_filename, cfg.progsec);

    int map_fd = find_map_fd(bpf_obj, cfg.mapname);
    if (map_fd < 0)
    {
        xdp_link_detach(cfg.netif_idx, cfg.xdp_flags, 0);
        return EXIT_FAIL_BPF;
    }

    struct bpf_map_info map_expected = {
        .key_size = sizeof(__u32),
        .value_size = sizeof(struct datarec),
        .max_entries = XDP_ACTION_MAX,
    };

    struct bpf_map_info info;
    int err = check_map_fd_info(map_fd, &info, &map_expected);
    if (err)
    {
        fprintf(stderr, "ERR: target map not match\n");
        return err;
    }

    

    return EXIT_OK;
}