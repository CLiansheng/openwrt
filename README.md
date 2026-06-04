# 计网实验 OpenWrt 项目说明

这个文件夹是《计算机网络系统》实验二：基于 OpenWrt 的网络应用程序开发项目。

项目已经完成到可以部署和录制演示视频的程度。队友需要做的主要事情是：启动 OpenWrt 虚拟机、上传运行包、按步骤演示、截图/录屏、完善报告中的个人信息和实际运行截图。

## 1. 文件夹里有什么

```text
计网实验/
  netpulse-openwrt/                 项目源码和文档
  netpulse-openwrt_代码.zip          提交用源码压缩包
  sdk/                              OpenWrt SDK，交叉编译用，体积较大
```

`netpulse-openwrt/` 里面：

```text
src/                 C 后端源码，负责抓包统计和 HTTP API
web/                 前端页面，展示流量监控和防火墙配置
scripts/             OpenWrt 启动脚本、防火墙脚本
build/               已编译和打包好的产物
docs/                使用文档、报告草稿、录屏脚本、交叉编译说明
README.md            项目技术说明
Makefile             编译和打包脚本
```

## 2. 最重要的两个文件

### 上传到 OpenWrt 运行的包

```text
netpulse-openwrt/build/netpulse-openwrt-upload.tar.gz
```

这个包用于上传到 OpenWrt 虚拟机中运行。

### 提交源码用的包

```text
netpulse-openwrt_代码.zip
```

这个是最终提交源码附件的基础版本。提交前请按老师要求改成包含组员姓名的文件名，例如：

```text
张三+李四+王五_代码.zip
```

## 3. OpenWrt 运行步骤

先启动 OpenWrt 虚拟机，进入控制台后查看 IP：

```sh
ip addr
```

检查是否联网：

```sh
ping 223.5.5.5
```

安装依赖：

```sh
opkg update
opkg install libpcap nftables
```

把这个文件上传到 OpenWrt 的 `/tmp/`：

```text
netpulse-openwrt/build/netpulse-openwrt-upload.tar.gz
```

可以在 Windows PowerShell 中执行，注意把 `OpenWrt_IP` 换成实际 IP：

```powershell
scp "C:\Users\admin\Desktop\计网实验\netpulse-openwrt\build\netpulse-openwrt-upload.tar.gz" root@OpenWrt_IP:/tmp/
```

然后 SSH 登录：

```powershell
ssh root@OpenWrt_IP
```

在 OpenWrt 中解压并运行：

```sh
mkdir -p /usr/local/netpulse
tar -xzf /tmp/netpulse-openwrt-upload.tar.gz -C /tmp
cp -r /tmp/netpulse-openwrt-upload/* /usr/local/netpulse/
cd /usr/local/netpulse
chmod +x netpulse_server scripts/*.sh
./scripts/run_openwrt.sh br-lan 8080
```

如果 `br-lan` 不存在，先用下面命令看接口名：

```sh
ip addr
```

然后把 `br-lan` 换成实际接口，例如：

```sh
./scripts/run_openwrt.sh eth0 8080
```

浏览器访问：

```text
http://OpenWrt_IP:8080
```

能看到 `NetPulse OpenWrt` 页面就说明服务启动成功。

## 4. 录视频怎么演示

建议照这个顺序录：

1. 展示项目目录和源码结构。
2. 展示 OpenWrt 虚拟机 IP 和联网状态。
3. 启动 `netpulse_server`。
4. 浏览器打开 `http://OpenWrt_IP:8080`。
5. 制造流量，展示流量表格和折线图变化。
6. 添加防火墙规则，展示规则列表。
7. 验证规则生效。
8. 清空规则，展示网络恢复。
9. 简单展示报告中的 AI 使用说明。

制造流量可以在 OpenWrt 里执行：

```sh
ping 223.5.5.5
opkg update
```

防火墙演示推荐添加 ICMP 阻断规则：

```text
协议：icmp
源地址：any
目的地址：any
端口：留空
动作：drop
```

然后在 Windows PowerShell 中验证：

```powershell
ping OpenWrt_IP
```

添加规则后应该 ping 不通。回到网页点击“清空实验规则”后，再 ping 应该恢复。

## 5. 报告和视频材料

文档都在：

```text
netpulse-openwrt/docs/
```

重要文档：

```text
使用文档.md          从部署到运行的完整步骤
实验报告草稿.md      报告初稿，需要补组员姓名、截图、实际实验现象
演示视频脚本.md      录屏讲稿和时间安排
部署与录屏步骤.md    适合边操作边看的步骤
交叉编译说明.md      编译说明，通常不用重新编译
```

报告里一定要保留并完善 AI 使用说明。实验指导书明确要求说明 AI 使用情况，否则可能影响成绩。

## 6. 队友分工建议

可以这样分：

```text
A 同学：负责 OpenWrt 虚拟机启动、联网、依赖安装、程序运行
B 同学：负责录屏，按演示视频脚本展示流量监控和防火墙配置
C 同学：负责实验报告，补截图、实验现象、AI 使用说明和总结
```

## 7. 注意事项

- `sdk/` 文件夹很大，是交叉编译用的，作业没交完前先不要删。
- `netpulse-openwrt-upload.tar.gz` 是给 OpenWrt 运行的，不是最终源码提交包。
- `netpulse-openwrt_代码.zip` 是源码提交包，提交前要按老师要求改成带组员姓名的文件名。
- 防火墙规则演示结束后一定要点“清空实验规则”，避免影响后续访问。
- 如果网页打不开，先检查 OpenWrt IP、服务是否还在运行、8080 端口是否被占用。

## 8. 常用排错命令

OpenWrt 中查看 IP：

```sh
ip addr
```

查看服务进程：

```sh
ps | grep netpulse
```

查看端口：

```sh
netstat -lntp | grep 8080
```

查看 nftables 规则：

```sh
nft -a list table inet netpulse
```

手动清空实验规则：

```sh
/usr/local/netpulse/scripts/firewall.sh clear
```
