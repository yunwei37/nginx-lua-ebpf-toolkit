

BPF_HASH(req_distr, u32, u64);

static void count_req(void)
{
    u32 pid;
    u64 *cnt, count = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    cnt = req_distr.lookup(&pid);
    if (cnt != NULL)
    {
        count = *cnt + 1;
    }
    req_distr.update(&pid, &count);
}

int check_ngx_http_create_request(struct pt_regs *ctx)
{
    count_req();
    return 0;
}
