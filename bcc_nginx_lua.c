#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>

typedef struct lua_State {
  unsigned long long nextgc; 
  unsigned char marked; 
  unsigned char gct;
  unsigned char  dummy_ffid;	/* Fake FF_C for curr_funcisL() on dummy frames. */
  unsigned char  status;	/* Thread status. */
  unsigned long long glref;		/* Link to global state. */
  unsigned long long gclist;		/* GC chain. */
  unsigned long long *base;		/* Base of currently executing function. */
  unsigned long long *top;		/* First free slot in the stack. */
  unsigned long long maxstack;	/* Last free slot in the stack. */
  unsigned long long *stack;		/* Stack base. */
  unsigned long long openupval;	/* List of open upvalues in the stack. */
  unsigned long long env;		/* Thread environment (table of globals). */
  unsigned long long *cframe;		/* End of C stack frame chain. */
  unsigned int stacksize;	/* True stack size (incl. LJ_STACK_EXTRA). */
  void *exdata;	        /* user extra data pointer. added by OpenResty */
  void *exdata2;	/* the 2nd user extra data pointer. added by OpenResty */
} lua_State;

BPF_HASH(req_distr, u32, u64);

static void count_req(lua_State *L)
{
    u32 pid;
    u64 *cnt, count = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    cnt = req_distr.lookup(&pid);
    if (cnt != NULL)
    {   
        //unsigned long long* stack = L->stack;
        count = L->stack;
    }
    req_distr.update(&pid, &count);
}


int check_ngx_http_lua_cache_load_code(struct pt_regs *ctx, void *log, lua_State *L,
    int *ref, const char *key)
{
    count_req(L);
    return 0;
}

int check_ngx_http_create_request(struct pt_regs *ctx)
{
    u32 pid;
    u64 *cnt, count = 0;
    pid = bpf_get_current_pid_tgid() >> 32;
    cnt = req_distr.lookup(&pid);
    if (cnt != NULL)
    {   
        count = *(cnt);
    }
    req_distr.update(&pid, &count);
    return 0;
}
