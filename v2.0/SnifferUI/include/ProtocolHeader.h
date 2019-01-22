//#include "pcap.h"
#define ETHERNET_HEADER_LENGTH	14
#define	UDP_HEADER_LENGTH		8

#define	ETHERNET_TYPE_IP		0x0800
#define	ETHERNET_TYPE_ARP		0x0806
#define PROTOCOL_ICMP			1
#define PROTOCOL_TCP			6
#define PROTOCOL_UDP			17
#define PORT_DNS				53
#define	PORT_DHCP_CLIENT		67
#define PORT_DHCP_SERVER		68
#define PORT_HTTP				80

#define ARP_OPCODE_REQUET		1
#define	ARP_OPCODE_REPLY		2

/**
*	@brief	ICMP_TYPE
*/
#define ICMP_TYPE_ECHO_REPLY				0
#define	ICMP_TYPE_DESTINATION_UNREACHABLE	3
#define ICMP_TYPE_SOURCE_QUENCH				4
#define ICMP_TYPE_REDIRECT					5
#define ICMP_TYPE_ECHO						8
#define ICMP_TYPE_ROUTER_ADVERTISEMENT		9
#define ICMP_TYPE_ROUTER_SOLICITATION		10
#define ICMP_TYPE_TIME_EXCEEDED				11
#define ICMP_TYPE_PARAMETER_PROBLEM			12
#define ICMP_TYPE_TIMESTAMP					13
#define ICMP_TYPE_TIMESTAMP_REPLY			14

/**
*	@brief	ICMP_CODE
*/
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE					0
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE					1
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE				2
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE					3
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_FRAGMENTATION_NEEDED_AND_DF_SET	4
#define ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_SOURCE_ROUTE_FAILED				5

#define ICMP_TYPE_SOURCE_QUENCH_CODE											0

#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK				0
#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST					1
#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK		2
#define ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST			3

#define ICMP_TYPE_ECHO_CODE														0

#define ICMP_TYPE_ROUTER_ADVERTISEMENT_CODE										0
#define ICMP_TYPE_ROUTER_SOLICITATION_CODE										0

#define ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT					0
#define ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE			1

#define ICMP_TYPE_PARAMETER_PROBLEM_CODE_POINTER_INDICATES_THE_ERROR			0	

#define ICMP_TYPE_TIMESTAMP_CODE												0




typedef struct MAC_Address
{
	u_char	bytes[6];

}MAC_Address;

typedef struct IP_Address
{
	u_char bytes[4];

}IP_Address;

typedef struct Ethernet_Header
{
	MAC_Address	dstaddr;		// 目的MAC地址
	MAC_Address	srcaddr;		// 源MAC地址	
	u_short		eth_type;		// 类型

}Ethernet_Header;

typedef struct IP_Header
{
	u_char		ver_headerlen ;	// 版本号(4 bits) + 首部长度(4 bits)
	u_char		tos;			// 服务类型
	u_short		totallen;		// 总长度
	u_short		identifier;		// 标识
	u_short		flags_offset;	// 标志(3 bits) + 片偏移(13 bits)
	u_char		ttl;			// 生存时间
	u_char		protocol;		// 上层协议
	u_short		checksum;		// 首部校验和
	IP_Address	srcaddr;		// 源地址
	IP_Address	dstaddr;		// 目的地址
	u_int		option_padding;	// 选项和填充

}IP_Header;


typedef struct ARP_Header
{
	u_short		hwtype;			// 硬件类型
	u_short		ptype;			// 协议类型
	u_char		hwlen;			// 硬件长度
	u_char		plen;			// 协议长度
	u_short		opcode;			// 操作码
	MAC_Address	srcmac;			// 源mac地址
	IP_Address	srcip;			// 源ip地址
	MAC_Address	dstmac;			// 目的mac地址
	IP_Address	dstip;			// 目的ip地址

}ARP_Header;

typedef struct ICMP_Header
{
	u_char		type;				// 类型
	u_char		code;				// 代码
	u_short		chksum;				// 校验和
	u_int		others;				// 首部其他部分（由报文类型来确定相应内容）

}ICMP_Header;

typedef struct TCP_Header
{
	u_short		srcport;				// 源端口
	u_short		dstport;				// 目的端口
	u_int		seq;					// 序号
	u_int		ack;					// 确认号
	u_short		headerlen_rsv_flags;	// 首部长度(4 bits) + 保留(6 bits) + 
										// URG(1 bit) + ACK(1 bit) + PSH(1 bit) + RST(1 bit) + SYN(1 bit) + FIN(1 bit)
	u_short		win_size;				// 窗口大小
	u_short		chksum;					// 校验和
	u_short		urg_ptr;				// 紧急指针
	u_int		option;					// 选项

}TCP_Header;

typedef struct UDP_Header
{
	u_short srcport;			// 源端口
	u_short dstport;			// 目的端口
	u_short	len;				// 长度
	u_short checksum;			// 校验和

}UDP_Header;

typedef struct DNS_Header
{
	u_short		identifier;		// 标识
	u_short		flags;			// 标志
	u_short		questions;		// 查询记录数
	u_short		answers;		// 回答记录数
	u_short		authority;		// 授权回答记录数
	u_short		additional;		// 附加信息记录数

}DNS_Header;

typedef struct DNS_Query
{
	u_short type;				// 查询类型
	u_short classes;			// 查询类

}DNS_Query;

typedef struct DNS_Answer
{
	u_short		type;				// 类型
	u_short		classes;			// 类
	u_int		ttl;				// 生存时间

}DNS_Answer;


/* chaddr字段到option字段在decodeDHCP中解析 */
typedef struct DHCP_Header
{
	u_char		op;					// 报文类型
	u_char		htype;				// 硬件类型
	u_char		hlen;				// 硬件地址长度
	u_char		hops;				// 跳数
	u_int		xid;				// 事务ID
	u_short		secs;				// 客户启动时间
	u_short		flags;				// 标志
	IP_Address	ciaddr;			// 客户机IP地址
	IP_Address	yiaddr;			// 你的IP地址
	IP_Address	siaddr;			// 服务器IP地址
	IP_Address	giaddr;			// 网关IP地址
//  u_char[16] chaddr;			// 客户硬件地址
//  u_char[64] sname;			// 服务器主机名
//  u_char[128] file;			// 启动文件名
//  options(variable)			// 选项（变长）
	
}DHCP_Header;



