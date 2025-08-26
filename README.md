一个类似 frp rathole 的内网穿透、服务共享工具<br>

An Intranet Penetration and Service Sharing Tool Similar to frp and rathole

### 主要功能 Features
- 单二进制文件集成服务端与客户端功能
- Single binary integrating both server and client functionalities
- 服务端、客户端可独立运行，也可运行在同一进程内
- Server and client can run independently or within the same process
- 服务端支持仅转发，无需暴露监听
- Server supports forwarding-only mode without exposing listening ports
- 同一客户端可连接多个服务端
- A single client can connect to multiple servers
- 客户端-服务端通讯使用Noise协议框架加密
- Client-server communication encrypted using the Noise Protocol Framework
- 客户端通过 http、socks5 代理连接服务器
- Client connects to servers via HTTP or SOCKS5 proxy
- 支持 TCP、UDP 协议
- Supports TCP and UDP protocols
- 断线重连
- Automatic reconnection upon disconnection
- 支持 nodelay keepalive 配置
- Supports nodelay and keepalive configuration
- 管理api、web管理（进行中）
- Management API and web management interface (in progress)

### 配置文件 Config file
```json
{
    "server": {
        "bindAddress": "0.0.0.0:17000",  // 服务端监听端口
        "psk": "1234qwer!",  // noise 加密通讯psk
        "service": {  // 服务配置
            "rdp_demo": {} // 每个服务一项，在服务端，服务的配置可以配成空对象
        }
    },
    "clients": [  // 客户端，一个客户端可以连接多个服务端
        {
            "serverAddress": "127.0.0.1:17000", // 服务端地址
            "psk": "1234qwer!",
            "service": { //服务配置
                "rdp_demo": {
                    "bindAddress": "127.0.0.1:14389",  // 该服务在本地的监听地址，配置bindAddress的服务是此项服务的消费者
                    "address": "192.168.124.14:3389" // 该服务上游提供者的地址，配置address的服务是此项服务的提供者
                }
            }
        }
    ]
}
```

### 命令行 Command line
```bash
ferry [-d] [./config.json]
```
