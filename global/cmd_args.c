#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <errno.h>
#include <linux/if_link.h>

#include "cmd_args.h"
#include "common_define.h"

int option_wrappers_to_options(
    const struct option_wrapper *wrappers,
    struct option **opts)
{
    size_t i, wrapper_size;
    for (i = 0; wrappers[i].option.name; i++)
        ;
    wrapper_size = i;

    struct option *new_opts = malloc(sizeof(struct option) * wrapper_size);
    if (!new_opts)
    {
        return -1;
    }
    for (size_t i = 0; i < wrapper_size; i++)
    {
        memcpy(&new_opts[i], &wrappers[i].option, sizeof(struct option));
    }

    *opts = new_opts;
    return 0;
}

void parse_cmd_args(
    int argc,
    char **argv,
    const struct option_wrapper *wrappers,
    struct config *cfg)
{
    struct option *opts;
    if (option_wrappers_to_options(wrappers, &opts))
    {
        fprintf(stderr, "acquire options failed\n");
        exit(EXIT_ACQUIRE_OPT_FAIL);
    }

    char *tmp_dest_addr;
    int opt_idx = 0, opt;
    while ((opt = getopt_long(
                argc,
                argv,
                "d:US",
                opts,
                &opt_idx)) != -1)
    {
        switch (opt)
        {
        case 'd':
            if (strlen(optarg) >= IF_NAMESIZE)
            {
                fprintf(stderr, "ERR: --dev name too long\n");
                goto error;
            }
            cfg->netif_name = (char *)&cfg->netif_name_buf;
            strncpy(cfg->netif_name, optarg, IF_NAMESIZE);
            cfg->netif_idx = if_nametoindex(cfg->netif_name);
            if (!cfg->netif_idx)
            {
                fprintf(stderr, "ERR: --dev name unknown err(%d):%s\n", errno, strerror(errno));
                goto error;
            }
            break;
        case 'U':
            cfg->do_unload = true;
            break;
        case 'S':
            cfg->xdp_flags &= ~XDP_FLAGS_MODES;
            cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;
            break;
        case 'M':
            cfg->reuse_maps = true;
            break;
        case 1:
            tmp_dest_addr = (char *)&cfg->progsec;
            strncpy(tmp_dest_addr, optarg, sizeof(cfg->progsec));
            break;
        case 2:
            tmp_dest_addr = (char *)&cfg->obj_filename;
            strncpy(tmp_dest_addr, optarg, sizeof(cfg->obj_filename));
            break;
        case 3:
            tmp_dest_addr = (char *)&cfg->pin_basedir;
            strncpy(tmp_dest_addr, optarg, sizeof(cfg->pin_basedir));
            break;
        case 4:
            tmp_dest_addr = (char *)&cfg->mapname;
            strncpy(tmp_dest_addr, optarg, sizeof(cfg->mapname));
            break;
        case 5:
            cfg->need_pin = true;
            break;
        error:
        default:
            free(opts);
            exit(EXIT_ACQUIRE_OPT_FAIL);
            break;
        }
    }
    free(opts);
}