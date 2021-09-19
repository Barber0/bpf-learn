#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "../common/common_define.h"
#include "../common/cmd_args.h"
#include "../common/xdp_helper.h"

static const char *default_bpf_obj_filename = "xdp_prog_kern.o";

struct option_wrapper wrappers[] = {
    {{"dev", required_argument, NULL, 'd'}, "device name", .required = true},
    {{"unload", no_argument, NULL, 'U'}, "unload or not"},
    {{"progsec", required_argument, NULL, 1}, "progsec", "haha"},
    {{"filename", required_argument, NULL, 2}, "filename", "<file>"},
};

int main(int argc, char *argv[])
{
    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .netif_idx = -1,
        .do_unload = false,
    };

    strncpy(cfg.obj_filename, default_bpf_obj_filename, sizeof(cfg.obj_filename));

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

    return EXIT_OK;
}
