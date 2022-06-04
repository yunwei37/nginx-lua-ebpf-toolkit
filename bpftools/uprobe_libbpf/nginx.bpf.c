/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "nginx.h"
#include "lua_state.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} starts_nginx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events_nginx SEC(".maps");


static int get_lua_stack(char* buf, struct lua_State* state) {

	return 0;
}


static int probe_entry_http(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct event event = {};

	if (target_pid && target_pid != pid)
		return 0;

	event.time = bpf_ktime_get_ns();
	event.pid = pid;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user(&event.host, sizeof(event.host), (void *)PT_REGS_PARM1(ctx));
	bpf_map_update_elem(&starts_nginx, &tid, &event, BPF_ANY);

	bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

static int probe_return(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&starts_nginx, &tid);
	if (!eventp)
		return 0;

	/* update time from timestamp to delta */
	eventp->time = bpf_ktime_get_ns() - eventp->time;
	bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	bpf_map_delete_elem(&starts_nginx, &tid);
	return 0;
}

static int probe_entry_lua(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM4(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct event event = {};

	if (target_pid && target_pid != pid)
		return 0;

	event.time = bpf_ktime_get_ns();
	event.pid = pid;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user(&event.host, sizeof(event.host), (void *)PT_REGS_PARM4(ctx));
	bpf_map_update_elem(&starts_nginx, &tid, &event, BPF_ANY);
	bpf_perf_event_output(ctx, &events_nginx, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("kprobe/handle_entry")
int handle_entry_lua(struct pt_regs *ctx)
{
	return probe_entry_lua(ctx);
}


SEC("kprobe/handle_entry")
int handle_entry_http(struct pt_regs *ctx)
{
	return probe_entry_http(ctx);
}

char LICENSE[] SEC("license") = "GPL";
