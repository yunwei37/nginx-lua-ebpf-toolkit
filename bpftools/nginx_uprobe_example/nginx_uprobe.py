import time
import bcc

data = open("bcc_nginx_req.c", 'r').read()
bpf = bcc.BPF(text=data)
bpf.attach_uprobe(name="/usr/local/openresty/nginx/sbin/nginx",
                  sym="ngx_http_create_request",
                  fn_name="check_ngx_http_create_request")
print("PID\treqs")
while True:
    data = bpf["req_distr"]
    for key, value in data. items():
        print("{0}\t{1}" .format(key. value, value. value))
        time.sleep(2)
