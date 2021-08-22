#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
	int btsLen = ctx->data_end - ctx->data;
	bpf_printk("pass pkt: %d\n", btsLen);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
