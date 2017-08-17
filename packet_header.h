#include "pcap.h"

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

}ip_address;

typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;

}mac_address;

typedef struct ip_header
{
	u_char		ver_hrdlen;		// 版本号(4 bits) + 首部长度(4 bits)
	u_char		tos;			// 服务类型
	u_short		totallen;		// 总长度
	u_short		identifier;	// 标识
	u_short		flags_offset;	// 标志(3 bits) + 片偏移(13 bits)
	u_char		ttl;			// 生存时间
	u_char		proto;			// 上层协议
	u_short		checksum;		// 首部校验和
	ip_address	srcaddr;		// 源地址
	ip_address	dstaddr;		// 目的地址
	u_int		option_padding;	// 选项和填充

}ip_header;


typedef struct arp_header
{
	u_short		hardtype;		// 硬件类型
	u_short		prototype;		// 协议类型
	u_char		hardlen;		// 硬件长度
	u_char		protolen;		// 协议长度
	u_short		op;				// 操作码
	mac_address	srcmac;			// 源mac地址
	ip_address	srcip;			// 源ip地址
	mac_address	dstmac;			// 目的mac地址
	ip_address  dstip;			// 目的ip地址

}arp_header;

typedef struct udp_header
{
	u_short srcport;			// 源端口
	u_short dstport;			// 目的端口
	u_short	len;				// 长度
	u_short checksum;			// 校验和

}udp_header;

typedef struct tcp_header
{
	u_short		srcport;			// 源端口
	u_short		dstport;			// 目的端口
	u_long		seq;				// 序号
	u_long		ack;				// 确认号
	u_short		hdrlen_rsv_flags;	// 首部长度(4 bits) + 保留(6 bits) + URG(1 bit) + ACK(1 bit) + PSH(1 bit) + RST(1 bit) + SYN(1 bit) + FIN(1 bit)
	u_short		win_size;			// 窗口大小
	u_short		chksum;				// 校验和
	u_short		urg_ptr;			// 紧急指针
	u_long		option;				// 选项

}tcp_header;

typedef struct dns_header
{
	u_short		identifier;			// 标识
	u_short		flags;				// 标志
	u_short		questions;			// 查询记录数
	u_short		answers;			// 回答记录数
	u_short		authority;			// 授权回答记录数
	u_short		additional;			// 附加信息记录数

}dns_header;

typedef struct dns_query
{
	u_short type;					// 查询类型
	u_short classes;				// 查询类

}dns_query;

typedef struct dns_answer
{
	u_short type;					// 类型
	u_short classes;				// 类
	u_long	ttl;					// 生存时间

}dns_answer;

typedef struct icmp_header
{
	u_char	type;					// 类型
	u_char	code;					// 代码
	u_short chksum;					// 校验和
	u_long  others;					// 首部其他部分（由报文类型来确定相应内容）

}icmp_header;

/* chaddr字段到option字段在decodeDHCP中解析 */
typedef struct dhcp_header
{
	u_char	op;						// 报文类型
	u_char	htype;					// 硬件类型
	u_char	hlen;					// 硬件地址长度
	u_char	hops;					// 跳数
	u_long	xid;					// 事务ID
	u_short secs;					// 客户启动时间
	u_short flags;					// 标志
	ip_address ciaddr;				// 客户机IP地址
	ip_address yiaddr;				// 你的IP地址
	ip_address siaddr;				// 服务器IP地址
	ip_address giaddr;				// 网关IP地址
//  u_char[16] chaddr;				// 客户硬件地址
//  u_char[64] sname;				// 服务器主机名
//  u_char[128] file;				// 启动文件名
//  options(variable)				// 选项（变长）
	
}dhcp_header;

typedef struct packet_header
{
	mac_address		saddr;			// 源mac地址
	mac_address		daddr;			// 目的mac地址
	u_short			eth_type;		// 以太网帧类型字段
	ip_header		*iph;			// ip首部
	arp_header		*arph;			// arp首部
	icmp_header     *icmph;			// icmp首部
	udp_header		*udph;			// udp首部
	tcp_header		*tcph;			// tcp首部
	dns_header		*dnsh;			// dns首部
	u_char			*pkt_data;		// 完整数据包
	int				caplen;			// 捕获数据包长度

}packet_header;



