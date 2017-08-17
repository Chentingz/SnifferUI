# SnifferUI
基于MFC和Winpcap库开发的抓包程序
* 支持对Ethernet、ARP、IPv4、ICMP、UDP、TCP、DNS、HTTP、DHCP的解析。
* 其中ICMP只支持解析类型为3、4、5、11、8、0的报文，DNS只支持解析类型A、NS、CNAME、PTR的报文，DHCP只能解析选项0、1、3、6、12、50、51、53、54、60、61、255。 

BUG:
* 内存泄露

ToDoList：
* 代码重构
