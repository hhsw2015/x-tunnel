# x-tunnel

https://019b6e9a-bcd3-79f6-9718-01dba6d633cb.arena.site/

https://019b6e9a-bcd3-7dd9-9c8a-49ed7acfe51d.arena.site/



🖥️ 服务端启动
```
# WSS 服务端 (自动生成证书)
$ x-tunnel -l wss://0.0.0.0:443/tunnel -token your-secret-token

# 带 SOCKS5 出口代理
$ x-tunnel -l wss://0.0.0.0:443/tunnel -f socks5://user:pass@127.0.0.1:1080
```

💻 客户端启动
```
# 启动 SOCKS5 + HTTP 代理
$ x-tunnel -l socks5://127.0.0.1:1080,http://127.0.0.1:8080 \
    -f wss://your-domain.com/tunnel -token your-secret-token \
    -ip 104.16.1.1,172.64.1.1 -n 4 -ips 4,6

# TCP 端口转发
$ x-tunnel -l tcp://127.0.0.1:2222/target.com:22 -f wss://...
```
