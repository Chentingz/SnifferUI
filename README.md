<p>
  <img src="https://github.com/Chentingz/SnifferUI/blob/master/SnifferUI/res/SnifferUI.ico" align=left border=0 />
  <h1>SnifferUI</h1>
</p>  
  
这是一款基于MFC和WinPcap库开发的网络抓包和协议分析软件，你可以用它来抓取本机网络流量，或者读取pcap文件离线分析流量。  

开发环境：Win7 + Visual Studio 2015  
依赖：WinPcap 4.1.3  

## 目录
- [功能](#功能)
- [运行截图](#运行截图)
  - [v2.0](#v20)
  - [v1.0](#v10)
- [更新说明](#更新说明)
- [ToDoList](#todolist)
- [Known Bug](#known-bug)
- [参考资料](#参考资料)

## 功能
* 实时网络数据包捕获和协议解析
* 支持实时、离线解析 *（实时：边抓包边解析 离线：读取pcap文件）*
* 提供显示过滤器
* 支持常见协议解析  
  * ICMP只支持解析类型为3、4、5、11、8、0的报文
  * DNS只支持解析类型A、NS、CNAME、PTR的报文
  * DHCP只能解析选项0、1、3、6、12、50、51、53、54、60、61、255  
    
    | 层次 | 协议 |
    | ------------------ | -----|
    | 应用层             | DNS / HTTP / DHCP |
    | 传输层             | UDP / TCP |
    | 网络层             | IPv4 / ICMP |
    | 数据链路层         | Ethernet / ARP |
  
* 支持快捷键  
    
    | 快捷键 | 功能 |
    | ------| -----|
    | Ctrl + G | 获得数据包列表中选中项焦点 |
    | Ctrl + O | 打开文件 |
    | Ctrl + W | 关闭文件 |
    | Ctrl + S | 另存为 |
    | Alt + F4 | 退出 |  

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
* 2019/6/24  
  - 完善菜单栏
    - 新增”清理缓存文件“菜单项
    - 新增”快捷键一览“菜单项
  - 新增工具栏
    - 原网卡列表、过滤器列表、按钮等移动至工具栏上
    - 用图标代替按钮文本
  - 完善数据包列表控件
    - 调整各列初始宽度
    - 允许拖拽列表的列
  - 完善状态栏
    - 调整各栏宽度
    - 新增“已显示”数据包个数
  - 完善“关于”窗口  
  
* 2019/5/23  
  * 代码重构
    * 新增PacketCatcher类、PacketDumper类、PacketPool类，降低抓包与界面之间耦合
    * PacketCatcher类：实现数据包捕获，底层使用winpcap库函数
    * PacketDumper类：实现捕获数据包转储到文件，仅支持转储.pcap文件
    * PacketPool类：实现数据包管理，底层使用stl关联容器map存储数据包
  * 新增菜单栏
  * 新增状态栏
  * 删除“暂停”按钮
  * 新增快捷键   
  
* 2019/1/22
  * 新增Packet类封装数据包，解决内存泄露问题
  * 界面更换为Win7风格
  
* 2019/1/14 
  * 新增显示过滤器
  
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

[回到顶部](#snifferui)
