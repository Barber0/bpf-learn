#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common_user_kern.h"
#include "../global/common_define.h"

struct bpf_map_def SEC("maps") xdp_stat_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

SEC("xdp_stat")
int xdp_stat_prog(struct xdp_md *ctx)
{
	__u32 key = XDP_PASS;
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stat_map, &key);
	if (!rec)
	{
		return XDP_ABORTED;
	}

	__sync_fetch_and_add(&rec->rx_pkts, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";