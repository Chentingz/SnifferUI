<p>
  <img src="https://github.com/Chentingz/SnifferUI/blob/master/SnifferUI/res/SnifferUI.ico" align=left border=0 />
  <h1>SnifferUI</h1>
</p>  

这是一款基于MFC和WinPcap库开发的网络抓包和协议分析软件，你可以用它来采集本机网络流量并在线分析协议，或者读取pcap文件进行离线协议分析，快[下载](https://github.com/Chentingz/SnifferUI/releases/tag/v2.0)试试吧。

开发环境：Win7 + Visual Studio 2015  
依赖：WinPcap 4.1.3  
技术细节：

- MFC搭建前端界面
- WinPcap实现本地网络接口抓包及pcap文件存储
- 利用STL的map容器实现内存中数据包管理
- 基于Windows消息队列实现线程间通信（抓包线程通知窗口线程解析和打印数据包或通知结束抓包释放资源）
- 从0到1自写了9种网络协议解析器

## 目录
- [功能](#功能)
- [运行截图](#运行截图)
  - [v2.0](#v20)
  - [v1.0](#v10)
- [更新说明](#更新说明)
- [ToDoList](#todolist)
- [Known Issues](#known-issues)
- [参考资料](#参考资料)

## 功能


* 本地网络接口上数据包实时捕获与在线协议分析
* 提供pcap文件存储
* 支持pcap文件读取与离线协议分析
* 提供显示过滤器，选择指定协议的数据包进行显示
* 支持常见网络协议解析  

  | 层次 | 协议 |
  | ------------------ | -----|
  | 应用层             | DNS / HTTP / DHCP |
  | 传输层             | UDP / TCP |
  | 网络层             | IPv4 / ICMP |
  | 数据链路层         | Ethernet / ARP |
  
  
  | ICMP报文类型 | ICMP报文类型值 | 支持解析 |
  | ------------ | -------------- | -------- |
  | 目的地不可达 | 3              | √        |
  | 源端抑制     | 4              | √        |
  | 重定向       | 5              | √        |
  | 超时         | 11             | √        |
  | Echo请求     | 8              | √        |
  | Echo响应     | 0              | √        |
  
  
  | DNS资源记录类型 | 作用                        | 支持解析 |
  | --------------- | --------------------------- | -------- |
  | A               | 根据域名查询IP地址          | √        |
  | NS              | 指定一个DNS服务器解析该域名 | √        |
  | CNAME           | 查询域名的别名              | √        |
  | PTR             | 根据IP地址查询域名          | √        |
  
  
  | DHCP报文选项   | DHCP报文选项代码 | 支持解析 |
  | -------------- | ---------------- | -------- |
  | 填充           | 0                | √        |
  | 子网掩码       | 1                | √        |
  | 网关地址       | 3                | √        |
  | DNS服务器地址  | 6                | √        |
  | 域名           | 12               | √        |
  | 请求IP地址     | 50               | √        |
  | IP地址租约时间 | 51               | √        |
  | DHCP消息类型   | 53               | √        |
  | DHCP服务器标识 | 54               | √        |
  | 厂商标识       | 60               | √        |
  | 客户端标识     | 61               | √        |
  | 结束           | 255              | √        |
  
* 支持快捷键  
  
    | 快捷键 | 功能 |
    | ------| -----|
    | Ctrl + G | 光标定位到当前选中数据包 |
    | Ctrl + O | 打开pcap文件 |
    | Ctrl + W | 关闭pcap文件 |
    | Ctrl + S | 另存为新的pcap文件 |
    | Alt + F4 | 退出程序 |

## 运行截图
### v2.0
<p align=center>
  <img src="https://github.com/Chentingz/SnifferUI/blob/master/img/SnifferUI_v2.0_Snapshot_20190624.png" width = 75% height = 75%/>
</p>  

### v1.0
<p align=center>
  <img src="https://github.com/Chentingz/SnifferUI/blob/v1.0/img/decode_dns.PNG" width = 75% height = 75%/>  
</p>  

## 更新说明
* 2021/4/11
  * 修复【点击'清除'按钮，不恢复显示所有数据包问题】
  * 修复【选择网卡与实际抓包网卡不一致问题】
  * 修复【进行新一轮抓包时，状态栏仍显示上一轮数据包捕获数量的问题】
  * 修复【在Win10上运行程序时报wpcap.dll出错问题】
* 2021/4/10
  * 新增【程序启动后自动创建tmp文件夹】
    * tmp文件夹用于存放实时抓包生成的pcap缓存文件
  * 修复【实时抓包时界面卡顿问题】
    * 抓包线程由原来的实时发送改为延时发送WM_PKTCATCH消息
* 2019/6/24  
  - 完善【菜单栏】
    - 新增”清理缓存文件“菜单项
    - 新增”快捷键一览“菜单项
  - 新增【工具栏】
    - 原网卡列表、过滤器列表、按钮等移动至工具栏上
    - 用图标代替按钮文本
  - 完善【数据包列表控件】
    - 调整各列初始宽度
    - 允许拖拽列表的列
  - 完善【状态栏】
    - 调整各栏宽度
    - 新增“已显示”数据包个数
  - 完善【“关于”窗口  】
* 2019/5/23  
  * 代码重构
    * 新增【PacketCatcher类、PacketDumper类、PacketPool类】，降低抓包与界面之间耦合
    * PacketCatcher类：实现数据包捕获，底层使用winpcap库函数
    * PacketDumper类：实现捕获数据包转储到文件，仅支持转储.pcap文件
    * PacketPool类：实现数据包管理，底层使用stl关联容器map存储数据包
  * 新增【菜单栏】
  * 新增【状态栏】
  * 删除【“暂停”按钮】
  * 新增【快捷键】   
* 2019/1/22
  * 新增【Packet类】封装数据包，解决内存泄露问题
  * 界面更换为Win7风格
* 2019/1/14 
  * 新增【显示过滤器】
* 2017/2/15 - 2017/3/12
  * 完成v1.0开发
  * 实现数据包实时捕获和常见协议解析
  
## ToDoList  
- [x] v2.0中DHCP,DNS,HTTP解析的实现  
- [x] 根据协议名过滤数据包  
- [x] 数据包保存为.pcap格式文件  
- [x] 鼠标移开list控件，保持选中行高亮 
- [x] 添加菜单栏  
- [ ] 优化内存占用率（目前抓取数据包数量很大时，内存占用率高）
- [x] 添加工具栏

## Known Issues
- [x] 过滤后原来位置的底色保持不变  
- [ ] DNS协议无法正确解析回答、授权回答、附加信息区域  
- [x] 数据包16进制字节流格式不对齐  
- [x] 按下结束后再开始，界面卡死  
- [x] 使用过滤器后，若线程仍在抓包，新抓到的的数据包没有过滤就打印
- [ ] 读取大pcap文件时，内存占用率高甚至出现程序崩溃 [#2](https://github.com/Chentingz/SnifferUI/issues/2)

## 参考资料
* [一步一步开发sniffer（Winpcap+MFC）（一）工欲善其事，必先配环境——配置winpcap开发环境](https://blog.csdn.net/litingli/article/details/5950962)
* [一步一步开发sniffer（Winpcap+MFC）（二）掀起你的盖头来，让我来画你的脸——用MFC开发GUI](https://blog.csdn.net/litingli/article/details/6098654)
* [一步一步开发sniffer（Winpcap+MFC）（三）安得广厦千万间，先画蓝图再砌砖——搭建winpcap抓包框架](https://blog.csdn.net/litingli/article/details/7315699)
* [一步一步开发sniffer（Winpcap+MFC）（四）要想从此过，留下协议头——各层网络协议头的实现](https://blog.csdn.net/litingli/article/details/7315789)
* [一步一步开发sniffer（Winpcap+MFC）（五）莫道无人能识君，其实我懂你的心——解析数据包](https://blog.csdn.net/litingli/article/details/7315914)
* [一步一步开发sniffer（Winpcap+MFC）（六）千呼万唤始出来，不抱琵琶也露面——将解析数据写到GUI上](https://blog.csdn.net/litingli/article/details/7316173)
* [RFC792 ICMP](https://www.rfc-editor.org/rfc/rfc792.txt)
* [RFC1257 ICMP Router Discovery Messages](https://www.rfc-editor.org/rfc/rfc1256.txt)
* [RFC1035  DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://www.rfc-editor.org/rfc/rfc1035.txt)
* [RFC2132 DHCP Options and BOOTP Vendor Extensions](https://www.rfc-editor.org/rfc/rfc2132.txt)
* [WinPcap 4.0.1中文技术文档](http://www.ferrisxu.com/WinPcap/html/index.html)
* [1184893257/SimpleSniffer](https://github.com/1184893257/SimpleSniffer)
* [（鸡啄米） VS2010/MFC编程入门教程之目录和总结](http://www.jizhuomi.com/software/257.html)  

## Stargazers over time

[![Stargazers over time](https://starchart.cc/Chentingz/SnifferUI.svg)](https://starchart.cc/Chentingz/SnifferUI)

[回到顶部](#snifferui)
