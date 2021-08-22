#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/consts.h"

struct bpf_object *__load_bpf_obj_file(const char *filename, int ifidx)
{
    int base_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex = ifidx,
    };

    prog_load_attr.file = filename;
    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &base_prog_fd);
    if (err)
    {
        fprintf(stderr, "[ERR] load BPF-OBJ file(%s) (%d): %s\n",
                filename, err, strerror(-err));
        return NULL;
    }

    return obj;
}

struct bpf_object *__load_bpf_and_xdp_attach(
    const char *filename,
    int ifidx)
{
    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    int prog_fd = -1;
    int err;

    bpf_obj = __load_bpf_obj_file(
        filename,
        ifidx);
    if (!bpf_obj)
    {
        fprintf(stderr, "[ERR]load file: %s\n", filename);
        exit(EXIT_FAIL_BPF);
    }
}

int main(int argc, char const *argv[])
{
    printf("ddd\n");
    printf("test: %s\n", "one-two-three");
    return 0;
}
