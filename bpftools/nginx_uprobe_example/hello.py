#!/usr/bin/env python3
# 1) 加载 BCC 库
from bcc import BPF

# 2) 加载 eBPF 内核态程序
b = BPF(src_file="test.c")

# 3) 将 eBPF 程序挂载到 kprobe
b.attach_kprobe(event="do_sys_openat2", fn_name="hello_world")

# 4) 读取并且打印 eBPF 内核态程序输出的数据
b.trace_print()

