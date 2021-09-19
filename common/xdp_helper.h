#ifndef __COMMON_XDP_HELPER_H
#define __COMMON_XDP_HELPER_H

#include <linux/types.h>
#include <bpf/bpf.h>

#include "common_define.h"

int xdp_link_attach(int ifidx, __u32 xdp_flags, int prog_fd);
int xdp_link_detach(int ifidx, __u32 xdp_flags, __u32 prog_id);

struct bpf_object *load_bpf_obj_file(const char *filename, int ifidx);
struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg);

#endif