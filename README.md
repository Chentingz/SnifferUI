# SnifferUI
基于MFC和Winpcap库开发的网络抓包软件  
开发环境：Win7 + Visual Studio 2015

## 功能：
* 支持常见协议解析  

  | 层次 | 协议 |
  | ------------------ | -----|
  | 应用层             | DNS / HTTP / DHCP |
  | 传输层             | UDP / TCP |
  | 网络层             | IPv4 / ICMP |
  | 数据链路层         | Ethernet / ARP |
  
* ICMP只支持解析类型为3、4、5、11、8、0的报文
* DNS只支持解析类型A、NS、CNAME、PTR的报文
* DHCP只能解析选项0、1、3、6、12、50、51、53、54、60、61、255

## ToDoList：  
- [x] v2.0中DHCP,DNS,HTTP解析的实现  
- [x] 根据协议名过滤数据包  
- [x] 数据包保存为.pcap格式文件  
- [x] 鼠标移开list控件，保持选中行高亮 
- [x] 添加菜单栏  
- [ ] 优化内存占用率（目前抓取数据包数量很大时，内存占用率高）
- [ ] 添加工具栏

## Known Bug：
- [x] 过滤后原来位置的底色保持不变  
- [x] DNS协议无法正确解析回答、授权回答、附加信息区域  
- [x] 数据包16进制字节流格式不对齐  
- [x] 按下结束后再开始，界面卡死  
- [x] 使用过滤器后，若线程仍在抓包，新抓到的的数据包没有过滤就打印


## v2.0更新说明：
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
  
    | 快捷键 | 功能 |
    | ------| -----|
    | Ctrl + G | 列表中选中数据包获得焦点 |
    | Ctrl + O | 打开文件 |
    | Ctrl + W | 关闭文件 |
    | Ctrl + S | 另存为 |
    | Alt + F4 | 退出 |  
    
* 2019/1/22
  * 新增Packet类封装数据包，解决内存泄露问题
  * 界面更换为WIN7风格

## 运行截图：
### v2.0
<img src="https://github.com/Chentingz/SnifferUI/blob/master/img/SnifferUI_v2.0_Snapshot_20190523.png" width = 75% height = 75%  />  

### v1.0
<img src="https://github.com/Chentingz/SnifferUI/blob/v1.0/img/decode_dns.PNG" width = 75% height = 75%  />  

<img src="https://github.com/Chentingz/SnifferUI/blob/v1.0/img/decode_dhcp.png" width = 75% height = 75%  />  

<img src="https://github.com/Chentingz/SnifferUI/blob/v1.0/img/decode_http.png" width = 75% height = 75%  />

## 参考资料：
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
