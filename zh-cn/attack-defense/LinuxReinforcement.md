# linux系统安全加固





# 1.身份鉴别

## 1.1 /etc/login.defs

### 1.1.1 文件功能

```python
查看密码策略
/etc/login.defs文件定义了与/etc/passwd和/etc/shadow配套的用户限制设置。
这个文件是一定要存在的，缺失并不会影响系统的使用，但是也许会产生意想不到的错误。

如果/etc/shadow文件里有相同的选项，则以/etc/shadow里的设置为准，
也就是说/etc/shadow的配置优先级高于/etc/login.defs。
```

### 1.1.2 文件内容

```python
#密码最大有效期，推荐 90
PASS_MAX_DAYS   99999
#两次修改密码的最小间隔时间
PASS_MIN_DAYS   0
#密码最小长度，对于root无效。#16位字符以上，包含大写字母、小写字母，数字，符合
PASS_MIN_LEN    5
#密码过期前多少天开始提示
PASS_WARN_AGE   7

#
UID_MIN                  1000
UID_MAX             
#USERDEL_CMD    /usr/sbin/userdel_local

#使用useradd的时候是够创建用户目录
CREATE_HOME     yes

#创建的用户目录的UMASK值
UMASK           077

#
USERGROUPS_ENAB yes

#Linux用户的密码使用SHA512散列模式加密
ENCRYPT_METHOD MD5

MD5_CRYPT_ENAB yes    60000
```



## 1.2 /etc/passwd

### 1.2.1 文件功能

```python
在Linux /etc/passwd文件中每个用户都有一个对应的记录行，它记录了这个用户的一些基本属性。
系统管理员经常会接触到这个文件的修改以完成对用户的管理工作。
```

### 1.2.2 文件内容

```python
cat /etc/passwd
root:x:0:0: root: /root:/bin/bash

root:用户名:代表用户账号的字符串
x:密码:加密后的用户口令字。虽然这个字段存放的只是用户口令的加密串，不是明文，
但是由于/etc/passwd文件对所有用户都可读，所以这仍是一个安全隐患。
因此，现在许多Linux系统都使用了shadow技术，
把真正的加密后的用户口令字存放到/etc/shadow文件中，
而在/etc/passwd文件的口令字段中只存放一个特殊的字符，例如“x”或者“*”。
0: UID:用户标识号
0: GID:用户组标识号
root:注释性描述
/root:主目录
/bin/bash:用户she11
```



## 1.3 /etc/shadow

### 1.3.1 文件功能

```python
检查空密码
前面介绍了/etc/passwd文件，由于该文件允许所有用户读取，易导致用户密码泄露，
因此Linux系统将用户的密码信息从/etc/passwd文件中分离出来，并单独放到了此文件中。

/etc/shadow文件只有root用户拥有读权限，其他用户没有任何权限，
这样就保证了用户密码的安全性。注意，如果这个文件的权限发生了改变，
则需要注意是否是恶意攻击。
```



### 1.3.2 文件内容

```python
cat /etc/shadowroot:
$6$k9s8ByZkt8sDNqBX$pT1H/2DwmmWHEzZwgywBV70mobuUBDvECD.9Qyw4iPdvK59c1cC6rBYL7THt4nnI47zd.QuTo8crrJY.wXUfx0:  :0:99999:7  :::

用户名
加密密码
最后一次修改时间
最小修改时间间隔
密码有效期
密码需要变更前的警告天数
密码过期后的宽限天数 #7天
账号失效时间
保留
```



# 2.访问控制

## 2.1 /etc/ssh/sshd_config

### 2.1.1 文件功能

```python
ssh配置功能
```



### 2.1.2 文件内容

```python
#默认端口，一般要修改掉
Port 22
#默认是全零网络，一般要配置成内网地址
ListenAddress 0.0.0.0
#连接主机时，输入密码的时间超过多长时间就断开，建议30s
LoginGraceTime 2m
#是否允许root登入，最好配置成 no
PermitRootLogin yes
#可以尝试输入密码的次数，超过次数，将会被锁定
MaxAuthTries 6
#同时发起登录请求的数量
Maxsessions 3
#客户端超时次数（输密码的次数），3
ClientAliveCountMax 3
```



## 2.2 /etc/bashrc

### 2.2.1 文件功能

```python
环境变量，初始化整个系统bash的设置
```

### 2.2.2 文件内容

```python

```

## 2.3 /etc/profile

### 2.3.1 文件功能

```python
环境变量，用于设置整个系统的环境变量
```

### 2.3.2 文件内容

```python
修改文件内容之后，需要重启服务。
source /etc/profile
```



## 2.4 /etc/hosts.deny

### 2.4.1 文件功能

```python
主机黑名单
```

### 2.4.2 文件内容

```python
#禁止所有主机
sshd:ALL
```

## 2.5 /etc/hosts.allow

### 2.5.1 文件功能

```python
主机白名单, hosts.allow与hosts.deny文件要同时配置才生效
```

### 2.5.2 文件内容

```python
#允许登录的主机
sshd:192.168.13.1
```



# 3.安全审计

## 3.1 /etc/rsyslog.conf

### 3.1.1 文件功能

```python
系统日志管理，配置安全日志的完备性
```

### 3.1.2 文件内容

```python
#修改之后需要重启机器，reboot
#将日期都输出到 /var/log/adm.log中
*.err;kern.debug;daemon.notice /var/log/adm.log
#将日志传输到指定ip:port上
*.*@192.168.0.1:514(可以将"*.*"替换为你实际需要的日志信息。
比如: kern.*mail.*等等。可以将此处192.168.0.1 替换为实际的IP或域名。)
```

### 3.1.3 想看history的具体信息

```python
1.修改bashrc
vi /etc/bashrc
HISTTIMEFORMAT="%F %T "
vi /etc/profile
HISTTIMEFORMAT="%F %T "

2.使其生效
source /etc/bashrc
source /etc/profile
```



# 4.资源控制(防止快捷键重启)

## 4.1 centos7

```python
cat /etc/inittab

#将文件中的内容全部注释掉。
vi /usr/lib/systemd/system/ctrl-alt-del.target

#重载配置使其生效
init q
```

# 5.入侵防范

## 5.1 关闭不必要的服务

```shell
主要防范的是各种的各样的服务，比如nginx,apache.
```



### 5.1.1 centos7

```shell
#查询开机自启的服务
systemctl list-unit-files | grep enable
#关闭开机自启的服务
systemctl disable nginx
```

### 5.1.2 centos6

```shell
chkconfig -list
chkconfig --level service 35 off
```


