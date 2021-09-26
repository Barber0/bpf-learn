#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>

#include "../global/common_define.h"
#include "../global/cmd_args.h"
#include "../global/xdp_helper.h"
#include "common_user_kern.h"

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

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
    char map_filename[PATH_MAX];
    char pin_dir[PATH_MAX];
    int err, len;

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", cfg->pin_basedir, cfg->netif_name);
    if (len < 0)
    {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_ACQUIRE_OPT_FAIL;
    }

    len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
                   cfg->pin_basedir, cfg->netif_name, cfg->mapname);
    if (len < 0)
    {
        fprintf(stderr, "ERR: creating map_name\n");
        return EXIT_ACQUIRE_OPT_FAIL;
    }

    /* Existing/previous XDP prog might not have cleaned up */
    if (access(map_filename, F_OK) != -1)
    {

        printf(" - Unpinning (remove) prev maps in %s/\n",
               pin_dir);

        /* Basically calls unlink(3) on map_filename */
        err = bpf_object__unpin_maps(bpf_obj, pin_dir);
        if (err)
        {
            fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
            return EXIT_FAIL_BPF;
        }
    }
    printf(" - Pinning maps in %s/\n", pin_dir);

    /* This will pin all maps in our bpf_object */
    err = bpf_object__pin_maps(bpf_obj, pin_dir);
    if (err)
        return EXIT_FAIL_BPF;

    return 0;
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    const struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (map)
    {
        fprintf(stderr, "ERR: find map by name failed: %s\n", mapname);
        return -1;
    }

    return bpf_map__fd(map);
}

int check_map_fd_info(int map_fd, struct bpf_map_info *info, struct bpf_map_info *exp)
{
    __u32 info_len = sizeof(*info);

    if (map_fd < 0)
    {
        return EXIT_FAIL;
    }

    int err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
    if (err)
    {
        fprintf(stderr, "ERR: %s() cant't get info: %s\n", __func__, strerror(-err));
        return EXIT_FAIL_BPF;
    }

    if (exp->key_size && exp->key_size != info->key_size)
    {
        fprintf(stderr, "ERR: %s() Map key size mismatch, expect(%d), found(%d)\n", __func__, exp->key_size, info->key_size);
        return EXIT_FAIL;
    }

    if (exp->value_size && exp->value_size != info->value_size)
    {
        fprintf(stderr, "ERR: %s() map value size mismatch, expect(%d), found(%d)\n", __func__, exp->value_size, info->value_size);
        return EXIT_FAIL;
    }

    if (exp->max_entries && exp->max_entries != info->max_entries)
    {
        fprintf(stderr, "ERR: %s() map max entries mismatch, expect(%d), found(%d)\n", __func__, exp->max_entries, info->max_entries);
        return EXIT_FAIL;
    }

    if (exp->type && exp->type != info->type)
    {
        fprintf(stderr, "ERR: %s() map type mismatch, expect(%u), found(%u)\n", __func__, exp->type, info->type);
        return EXIT_FAIL;
    }

    return 0;
}

struct record
{
    __u64 ts;
    struct datarec total;
};

struct stats_record
{
    struct record stats[1];
};

#define NANOSEC_PER_SEC 1000000000
__u64 gettime()
{
    struct timespec t;
    int res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0)
    {
        fprintf(stderr, "ERR: get time failed(%d)\n", res);
        exit(EXIT_FAIL);
    }
    return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
    if (bpf_map_lookup_elem(fd, &key, value))
    {
        fprintf(stderr, "ERR: bpf map lookup elem failed: key(0x%X)\n", key);
    }
}

bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
    struct datarec value;
    rec->ts = gettime();

    switch (map_type)
    {
    case BPF_MAP_TYPE_ARRAY:
        map_get_value_array(fd, key, &value);
        break;
    case BPF_MAP_TYPE_PERCPU_HASH:
    default:
        fprintf(stderr, "ERR: unknown map_type(%u) can't handle\n", map_type);
        return false;
        break;
    }

    rec->total.rx_pkts = value.rx_pkts;
    return true;
}

void stats_print(__u32 key, struct stats_record *stats_rec, struct stats_record *stats_prev)
{
    struct record *rec = &stats_rec->stats[0],
                  *prev = &stats_prev->stats[0];

    __u64 tmp_period = rec->ts - prev->ts;
    double period = 0;
    if (tmp_period > 0)
    {
        period = ((double)tmp_period / NANOSEC_PER_SEC);
    }

    if (!period)
    {
        return;
    }

    __u64 pkts = rec->total.rx_pkts - prev->total.rx_pkts;
    double pps = (double)pkts / period;

    printf("%-12s %lld pkts (%'10.0f pps) period(%f)\n", action2str(key), pkts, pps, period);
}

void stats_poll(int map_fd, __u32 map_type, int interval)
{
    setlocale(LC_NUMERIC, "en_US");

    __u32 key = XDP_PASS;
    struct stats_record record = {0};
    map_collect(map_fd, map_type, key, &record.stats[0]);
    usleep(1000000 / 4);

    struct stats_record prev;
    while (1)
    {
        prev = record;
        map_collect(map_fd, map_type, key, &record.stats[0]);
        stats_print(key, &record, &prev);
        sleep(interval);
    }
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