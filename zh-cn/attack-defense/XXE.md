# XXE攻击与防御

# 1.XXE攻击概述

```shell
XXE简介:
XXE 全称是XML External Entity,也就是XML外部实体注入攻击。
漏洞是在对不安全的外部实体数据进行处理时引发的安全问题。

```

## 1.1 示例

```shell
在2018年7月-4日，微信支付的SDK曝出重大漏洞-XXE漏洞.
漏洞报告地址:
http://seclists.org/fulldisclosure/2018/Jul/3

其他。
```

## 1.2 XML简介

```shell
XML被设计用来传输和存储数据。
XML文档形成了一种树结构,它从“根部“开始然后扩展到"枝叶"。
XML允许创作者定义自己的标签和自己的文档结构。
```

### 1.2.1 XML语法规则

```shell
XML的语法规则:
1、所有的XML元素必须要有一个关闭的标签
2、XML严重区分大小写
3、需要有正确的嵌套
4、XML标签属性中的值需要使用引号指定
5、实体引用
6、XML文档中，空格会被保留
```

### 1.2.2 XML数据结构示例

```shell
vi demo.xml

<note>
    <from>tom</from>
    <to>jerry</to>
    <address>nj</address>
</note>

```

### 1.2.3 实体引用

```shell
由于特殊符号含有特殊的意义，为避免产生冲突，因此需要使用实体代替特殊符号。在xml中，常用的
有5个预定的实体引用的符号：
&lt;    <  小于号
&gt;    >  大于号
&amp;   &  和号
&apos;  '  单引号
&quot;  "  双引号
```

### 1.2.4 注释

```shell
<!-- 这里是注释 -->
<msg>hello</msg>
```

## 1.3 XML-DTD

### 1.3.1 概述

```shell
“形式良好"或者“结构良好”:表示拥有语法正确XML。

DTD就是用于验证 XML合法性
DTD 中文“文档类型定义”

按如下规则:
(1)XML文档必须有根元素
(2)XML文档必须有关闭标签
(3)XML标签对区分大小写
(4)XML元素必须需要使用正确的嵌套.
(5)XML标签属性的值必须加引号指定

手工检查XML文档是否是形式良好的文档的效率太低，因此可以使用工具进行自动检查。

XML引用DTD检测的方法通常有两种:
一、直接在XML文档声明并进行引用。
二、在XML文档中引入一个外部的DTD 检测文件。
```

### 1.3.2 在XML文档声明并进行引用XML-DTD

```shell

<?xml version="1.0"?>
<!DOCTYPE node[
  <!ELEMENT node (name,age,address)>
  <!ELEMENT name (#PCDATA)>
  <!ELEMENT age (#PCDATA)>
  <!ELEMENT address (#PCDATA)>
]>
<node>
        <name>tom</name>
        <age>31</age>
        <address>bj</address>
</node>
```



### 1.3.3 在XML文档中引入一个外部的DTD 检测文件

```shell
vi t3.dtd
<!ELEMENT node (name,age,address)>
<!ELEMENT name (#PCDATA)>
<!ELEMENT age (#PCDATA)>
<!ELEMENT address (#PCD)>

vi t3.xml
<?xml version="1.0" ?>
<!DOCTYPE node SYSTEM "t3.dtd">
<node>
        <name>tim</name>
        <age>34</age>
        <address>tj</address>
</node>
```



# 2.XXE 漏洞演示

## 2.1 centos

```shell
XXE 漏洞在CENTOS中已经被修复。
```



## 2.2 java

```shell

```



# 3.XXE漏洞防御

```shell
1.升级 libxml版本
libxml2.9.0以后，默认不解析外部实体

2.代码层防御
使用开发语言提供的禁用外部实体的方法

2.1 PHP
libxml_disable_entity_loader(true);

2.2 java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setExpandEntityReferences(false);

2.3 python
from lxml import etree
xmlData = etree.parse(xmlSource,etree,XMLParser(resolve_entities=False))

3.过滤用户提交的数据
关键词<!DOCTYPE和<!ENTITY,或,SYSTEM和PUBLIC
```


