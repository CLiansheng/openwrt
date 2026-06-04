# NetPulse OpenWrt 实验项目

本项目用于《计算机网络系统》实验二：基于 OpenWrt 的网络应用程序开发。项目实现了两个功能：

- 基于 `libpcap` 的实时流量监控，统计源/目的 IP、累计接收/发送流量、峰值速率、过去 2s/10s/40s 平均速率。
- 基于 Web 的防火墙规则配置，支持新增、查看、删除、清空实验规则，并通过白名单参数和脚本封装避免直接拼接用户命令。

## 目录结构

```text
netpulse-openwrt/
  src/netpulse_server.c      C 语言主程序：抓包统计 + HTTP API + 静态页面服务
  web/                       前端页面
  scripts/firewall.sh        nftables 防火墙规则脚本
  scripts/run_openwrt.sh     OpenWrt 运行脚本
  scripts/netpulse.init      可选 procd 服务脚本
  docs/                      部署说明、报告草稿、视频脚本
  Makefile                   编译与打包
```

## OpenWrt 依赖

```sh
opkg update
opkg install libpcap nftables
```

如果需要在 OpenWrt 虚拟机内直接编译，还需要安装 `gcc make libpcap-dev`，但 OpenWrt overlay 空间经常不足，推荐在 SDK 或 Linux/WSL 环境中交叉编译后传入 OpenWrt。

## 编译

普通 Linux 环境：

```sh
make
```

OpenWrt SDK 交叉编译示例：

```sh
export STAGING_DIR=/path/to/openwrt-sdk/staging_dir
export TARGET_DIR=$STAGING_DIR/target-x86_64_musl
export TOOLCHAIN_DIR=$STAGING_DIR/toolchain-x86_64_gcc-*_musl
export PATH=$TOOLCHAIN_DIR/bin:$PATH

make clean
make openwrt-dynamic CC=x86_64-openwrt-linux-musl-gcc
```

编译结果为：

```text
build/openwrt/netpulse_server
```

`openwrt-dynamic` 版本在运行时加载 `libpcap.so.1`，因此 OpenWrt 上需要安装 `libpcap`，但交叉编译阶段不需要准备 `libpcap-dev`。

打包上传目录：

```sh
make package-openwrt CC=x86_64-openwrt-linux-musl-gcc
```

生成：

```text
build/netpulse-openwrt-upload.tar.gz
```

## 部署到 OpenWrt

将以下内容复制到 OpenWrt 的 `/usr/local/netpulse`：

```text
build/openwrt/netpulse_server
web/
scripts/
```

在 OpenWrt 中执行：

```sh
cd /usr/local/netpulse
chmod +x netpulse_server scripts/*.sh
./scripts/run_openwrt.sh br-lan 8080
```

然后在宿主机浏览器访问：

```text
http://OpenWrt_IP:8080
```

如果抓包接口不是 `br-lan`，先执行 `ip addr` 查看接口名，再替换运行命令中的接口参数。

## API 说明

```text
GET  /api/traffic
GET  /api/firewall/list
POST /api/firewall/add
POST /api/firewall/delete
POST /api/firewall/clear
```

新增防火墙规则请求示例：

```json
{
  "protocol": "tcp",
  "src": "any",
  "dst": "192.168.1.1",
  "port": "80",
  "action": "drop"
}
```

## 演示建议

1. 启动 OpenWrt 虚拟机并确认宿主机可以访问 OpenWrt。
2. 启动 NetPulse 服务，浏览器打开 Web 页面。
3. 用 `ping`、浏览 LuCI、`opkg update` 等方式制造流量，展示流量表格和折线图变化。
4. 添加一条防火墙规则，例如阻断某个 TCP 端口或 ICMP。
5. 展示规则列表，再执行访问验证。
6. 删除或清空实验规则，展示恢复结果。

## 安全设计说明

后端不直接执行前端提交的完整命令，只允许固定接口调用 `scripts/firewall.sh`。参数经过白名单校验：

- 协议只允许 `all/tcp/udp/icmp`
- 动作只允许 `accept/reject/drop`
- 防火墙 IP 地址只允许空、`any`、IPv4 或 IPv4 CIDR
- 端口只允许空、`any` 或 1 到 65535

脚本内部也进行了二次校验，并把实验规则放在独立的 `inet netpulse` 表中，便于查看和清理。
