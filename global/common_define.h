#ifndef __COMMON_COMMON_DEFINE_H
#define __COMMON_COMMON_DEFINE_H

#include <net/if.h>
#include <stdbool.h>
#include <linux/types.h>

struct config
{
    char *netif_name;
    char netif_name_buf[IF_NAMESIZE];
    int netif_idx;
    bool do_unload;
    char progsec[512];
    char obj_filename[512];

    bool need_pin;
    char pin_basedir[512];
    bool reuse_maps;
    char pin_dir[512];
    char mapname[512];
    __u32 xdp_flags;
};

#define EXIT_OK 0
#define EXIT_ACQUIRE_OPT_FAIL 1
#define EXIT_FAIL_XDP 2
#define EXIT_FAIL 3
#define EXIT_FAIL_BPF 4

#define XDP_UNKNOWN XDP_REDIRECT + 1

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX XDP_UNKNOWN + 1
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#endif