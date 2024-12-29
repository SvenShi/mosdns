# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)
# ospf-mosdns
本项目仅对原版基础上添加了ospf插件用于dns解析后动态将解析结果添加到路由中

### Config Example
``` yaml
  - tag: ospf
    type: ospf
    args:
      #路由有效时间（秒），过期后删除路由，如果有dns缓存需要大于dns缓存时间
      ttl: 21600
      #本机ip 加上局域网子网cidr
      ip: 172.16.2.53/24
      #本机和路由连接的网口
      iface: eth0
      #需要将路由添加到那个routerId中，如果对应本机直接填本机ip
      routerId: 172.16.2.254
      #永久静态路由，mosdns运行期间持续存在的路由,将指定ip数据路由到routerId的路由器中
      persistentRoute:
        #ips:
        #  - "192.168.1.1"
        #  - "192.168.1.0/24"
        files:
          - "/opt/mosdns/dat/geoip_telegram.txt"

  - tag: remote_sequence
    type: sequence
    args:
      - exec: $forward_remote
      #将解析后的dns结果保存到路由表中
      - exec: $ospf
```
### 注意项
1. 如果RouterId为非本机IP，需要对应的RouterId路由在ospf邻居列表中
2. 当前版本仅简单使用版，可能有未知问题





### 致谢
ospf调用相关代码来源@povsister


https://github.com/povsister/v2ray-core
