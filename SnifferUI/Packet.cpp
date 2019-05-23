#include "stdafx.h"
#include "Packet.h"
#include "pcap.h"
Packet::Packet()
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;

	pkt_data = NULL;
	num = -1;
	header = NULL;
}

Packet::Packet(const Packet &p)
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;

	if (!p.isEmpty())
	{
		u_int caplen = p.header->caplen;

		pkt_data = (u_char*)malloc( caplen );
		memcpy(pkt_data, p.pkt_data, caplen);

		header = (struct pcap_pkthdr *)malloc(sizeof( *(p.header) ));
		memcpy(header, p.header, sizeof(*(p.header)));
		
		num = p.num;

		decodeEthernet();
	}
	else
	{
		pkt_data = NULL;
		header = NULL;
		num = -1;
	}
}

Packet::Packet(const struct pcap_pkthdr *header,const u_char *pkt_data, const u_short &packetNum)
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;
	num = packetNum;

	if (pkt_data != NULL && header != NULL)
	{
		this->pkt_data = (u_char*)malloc(header->caplen);
		memcpy(this->pkt_data, pkt_data, header->caplen);

		this->header = (struct pcap_pkthdr *)malloc(sizeof(*header));
		memcpy(this->header, header, sizeof(*header));

		decodeEthernet();
	}
	else
	{
		this->pkt_data = NULL;
		this->header = NULL;
	}
}

/**
*	@brief	赋值运算符函数
*	@param	p	数据包
*	@return 实例本身
*/
Packet & Packet::operator=(const Packet & p)
{
	if (this == &p)
	{
		return *this;
	}
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;


	if (!p.isEmpty())
	{
		u_int caplen = p.header->caplen;

		if (pkt_data == NULL)
		{
			pkt_data = (u_char*)malloc(caplen);
		}
		memcpy(pkt_data, p.pkt_data, caplen);

		if (header == NULL)
		{
			header = (struct pcap_pkthdr *)malloc(sizeof(*(p.header)));
		}
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	}
	else
	{
		pkt_data = NULL;
		header = NULL;
		httpmsg = NULL;
		num = -1;
	}
	return *this;
}

Packet::~Packet()
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;
	num = -1;

	free(pkt_data);
	pkt_data = NULL;

	free(header);
	header = NULL;
	protocol.Empty();
}

/**
*	@brief	判断数据包是否为空
*	@param	-
*	@return true pkt_data或header为空	false pkt_data和header都不空
*/
bool Packet::isEmpty() const
{
	if (pkt_data == NULL || header == NULL)
	{
		return true;
	}
	return false;
}

/**
*	@brief	解析Ethernet帧，用成员变量ethh保存，根据eth_type值调用下一个解析器
*	@param	-
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeEthernet()
{
	if (isEmpty())
	{
		return -1;
	}

	protocol = "Ethernet";
	ethh = (Ethernet_Header*)pkt_data;
	
	switch (ntohs(ethh->eth_type))
	{
		case ETHERNET_TYPE_IP:
			decodeIP(pkt_data + ETHERNET_HEADER_LENGTH);
			break;
		case ETHERNET_TYPE_ARP:
			decodeARP(pkt_data + ETHERNET_HEADER_LENGTH);
			break;
		default:
			break;
	}
	return 0;
}

/**
*	@brief	解析IP数据包首部，用成员变量iph保存，根据protocol值调用下一个解析器
*	@param	L2payload	指向IP数据包的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeIP(u_char * L2payload)
{
	if (L2payload == NULL)
	{
		return -1;
	}

	protocol = "IPv4";
	iph = (IP_Header*)(L2payload);
	u_short IPHeaderLen = (iph->ver_headerlen & 0x0f) * 4;
	switch (iph->protocol)
	{
		case PROTOCOL_ICMP:		
			decodeICMP(L2payload + IPHeaderLen);
			break;	

		case PROTOCOL_TCP:		
			decodeTCP(L2payload + IPHeaderLen);
			break;	

		case PROTOCOL_UDP:
			decodeUDP(L2payload + IPHeaderLen);
			break;	

		default:
			break;
	}
	return 0;
}

/**
*	@brief	解析ARP报文首部，用成员变量arph保存
*	@param	L2payload	指向ARP报文的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeARP(u_char * L2payload)
{
	if (L2payload == NULL)
	{
		return -1;
	}
	protocol = "ARP";
	arph = (ARP_Header*)(L2payload);

	return 0;
}

/**
*	@brief	解析ICMP报文首部，用成员变量icmph保存
*	@param	L2payload	指向ICMP报文的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeICMP(u_char * L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "ICMP";
	icmph = (ICMP_Header*)(L3payload);
	return 0;
}

/**
*	@brief	解析TCP报文段首部，用成员变量tcph保存，根据源目端口选择下一个解析器
*	@param	L3payload	指向TCP报文段的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeTCP(u_char * L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "TCP";
	tcph = (TCP_Header*)(L3payload);

	u_short TCPHeaderLen = (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;
	if (ntohs(tcph->srcport) == PORT_DNS || ntohs(tcph->dstport) == PORT_DNS)
	{
		decodeDNS(L3payload + TCPHeaderLen);
	}
	else if (ntohs(tcph->srcport) == PORT_HTTP || ntohs(tcph->dstport) == PORT_HTTP)
	{
		int HTTPMsgLen = getL4PayloadLength();
		if (HTTPMsgLen > 0)
		{
			decodeHTTP(L3payload + TCPHeaderLen);
		}
		
	}
	return 0;
}

/**
*	@brief	解析UDP用户数据报首部，用成员变量udph保存，根据源目端口选择下一个解析器
*	@param	L2payload	指向UDP用户数据报的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeUDP(u_char *L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "UDP";
	udph = (UDP_Header*)(L3payload);
	if (ntohs(udph->srcport) == PORT_DNS || ntohs(udph->dstport) == PORT_DNS)
	{
		decodeDNS(L3payload + UDP_HEADER_LENGTH);

	}
	else if ((ntohs(udph->srcport) == PORT_DHCP_CLIENT && ntohs(udph->dstport) == PORT_DHCP_SERVER) || (ntohs(udph->srcport) == PORT_DHCP_SERVER && ntohs(udph->dstport) == PORT_DHCP_CLIENT))
	{
		decodeDHCP(L3payload + UDP_HEADER_LENGTH);
	}
	return 0;
}

/**
*	@brief	解析DNS报文首部，用成员变量dnsh保存
*	@param	L4payload	指向DNS报文的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeDNS(u_char * L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "DNS";
	dnsh = (DNS_Header*)(L4payload);
	return 0;
}

/**
*	@brief	解析DHCP报文首部，用成员变量dhcph保存
*	@param	L4payload	指向DHCP报文的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeDHCP(u_char * L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "DHCP";
	dhcph = (DHCP_Header*)L4payload;
	return 0;
}

/**
*	@brief	解析HTTP报文首部，用成员变量httpmsg保存
*	@param	L4payload	指向httpmsg报文的指针
*	@return	0 表示解析成功	-1 表示解析失败
*/
int Packet::decodeHTTP(u_char * L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "HTTP";
	httpmsg = L4payload;
	return 0;
}

/**
*	@brief	获取IP首部长度
*	@param	-
*	@return IP首部长度
*/
int Packet::getIPHeaderLegnth() const
{
	if (iph == NULL)
		return -1;
	else
		return (iph->ver_headerlen & 0x0F) * 4;
}

/**
*	@brief	获取IP首部长度原始值
*	@param	-
*	@return IP首部长度原始值	-1	IP首部为空
*/
int Packet::getIPHeaderLengthRaw() const
{
	if (iph == NULL)
		return -1;
	else
		return (iph->ver_headerlen & 0x0F);
}

/**
*	@brief	获取IP首部标志
*	@param	-
*	@return IP首部标志	-1	IP首部为空
*/
int Packet::getIPFlags() const
{
	if (iph == NULL)
		return -1;
	else
		return ntohs(iph->flags_offset) >> 13;
}

/**
*	@brief	获取IP首部标志DF位
*	@param	-
*	@return IP首部标志DF位	-1	IP首部为空
*/
int Packet::getIPFlagDF() const
{
	if (iph == NULL)
		return -1;
	else
		return (ntohs(iph->flags_offset) >> 13) & 0x0001;
}

/**
*	@brief	获取IP首部标志MF位
*	@param	-
*	@return IP首部标志MF位	-1	IP首部为空
*/
int Packet::getIPFlagsMF() const
{
	if (iph == NULL)
		return -1;
	else
		return (ntohs(iph->flags_offset) >> 14) & 0x0001;
}

/**
*	@brief	获取IP首部片偏移
*	@param	-
*	@return IP首部片偏移	-1	IP首部为空
*/
int Packet::getIPOffset() const
{
	if (iph == NULL)
		return -1;
	else
		return	ntohs(iph->flags_offset) & 0x1FFF;
}

/**
*	@brief	获取ICMP首部Other字段中的Id
*	@param	-
*	@return ICMP首部Other字段中的Id	-1	ICMP首部为空
*/
u_short Packet::getICMPID() const
{
	if (icmph == NULL)
		return -1;
	else
	return (u_short)(ntohl(icmph->others) >> 16);
}

/**
*	@brief	获取ICMP首部Other字段中的Seq
*	@param	-
*	@return ICMP首部Other字段中的Seq	-1	ICMP首部为空
*/
u_short Packet::getICMPSeq() const
{
	if (icmph == NULL)
		return -1;
	else
		return (u_short)(ntohl(icmph->others) & 0x0000FFFF);
}

/**
*	@brief	获取TCP首部长度
*	@param	-
*	@return TCP首部长度	-1	TCP首部为空
*/
int Packet::getTCPHeaderLength() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;
}

/**
*	@brief	获取TCP首部长度原始值
*	@param	-
*	@return TCP首部长度原始值	-1	TCP首部为空
*/
int Packet::getTCPHeaderLengthRaw() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 12) ;
}

/**
*	@brief	获取TCP首部标志
*	@param	-
*	@return TCP首部标志	-1	TCP首部为空
*/
u_short Packet::getTCPFlags() const
{
	if (tcph == NULL)
		return -1;
	else
		return  ntohs(tcph->headerlen_rsv_flags) & 0x0FFF;
}

/**
*	@brief	获取TCP首部标志URG
*	@param	-
*	@return TCP首部标志URG	-1	TCP首部为空
*/
int Packet::getTCPFlagsURG() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 5) & 0x0001;
}

/**
*	@brief	获取TCP首部标志ACK
*	@param	-
*	@return TCP首部标志ACK	-1	TCP首部为空
*/
int Packet::getTCPFlagsACK() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 4) & 0x0001;
}

/**
*	@brief	获取TCP首部标志PSH
*	@param	-
*	@return TCP首部标志PSH	-1	TCP首部为空
*/
int Packet::getTCPFlagsPSH() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 3) & 0x0001;
}

/**
*	@brief	获取TCP首部标志RST
*	@param	-
*	@return TCP首部标志RST	-1	TCP首部为空
*/
int Packet::getTCPFlagsRST() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 2) & 0x0001;
}

/**
*	@brief	获取TCP首部标志SYN
*	@param	-
*	@return TCP首部标志SYN	-1	TCP首部为空
*/
int Packet::getTCPFlagsSYN() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 1) & 0x0001;
}

/**
*	@brief	获取TCP首部标志FIN
*	@param	-
*	@return TCP首部标志FIN	-1	TCP首部为空
*/
int Packet::getTCPFlagsFIN() const
{
	if (tcph == NULL)
		return -1;
	else
		return ntohs(tcph->headerlen_rsv_flags) & 0x0001;
}
/**
*	@brief 获取应用层消息长度
*	@param	-
*	@return 应用层消息长度
*/
int Packet::getL4PayloadLength() const
{
	if (iph == NULL || tcph == NULL)
	{
		return 0;
	}
	int IPTotalLen = ntohs(iph->totallen);
	int IPHeaderLen = (iph->ver_headerlen & 0x0F) * 4;
	int TCPHeaderLen = (ntohs(tcph->headerlen_rsv_flags) >> 12 ) * 4;

	return IPTotalLen - IPHeaderLen - TCPHeaderLen ;
}

/**
*	@brief	获取DNS首部标志QR
*	@param	-
*	@return DNS首部标志QR	-1	DNS首部为空
*/
int Packet::getDNSFlagsQR() const
{
	if (dnsh == NULL)
		return -1;
	else
		return	dnsh->flags >> 15;
}

/**
*	@brief	获取DNS首部标志OPCODE
*	@param	-
*	@return DNS首部标志OPCODE	-1	DNS首部为空
*/
int Packet::getDNSFlagsOPCODE() const
{
	if (dnsh == NULL)
		return -1;
	else
		return	(ntohs(dnsh->flags) >> 11) & 0x000F;
}

/**
*	@brief	获取DNS首部标志AA
*	@param	-
*	@return DNS首部标志AA	-1	DNS首部为空
*/
int Packet::getDNSFlagsAA() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 10) & 0x0001;
}

/**
*	@brief	获取DNS首部标志TC
*	@param	-
*	@return DNS首部标志TC	-1	DNS首部为空
*/
int Packet::getDNSFlagsTC() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 9) & 0x0001;
}

/**
*	@brief	获取DNS首部标志RD
*	@param	-
*	@return DNS首部标志RD	-1	DNS首部为空
*/
int Packet::getDNSFlagsRD() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 8) & 0x0001;
}

/**
*	@brief	获取DNS首部标志RA
*	@param	-
*	@return DNS首部标志RA	-1	DNS首部为空
*/
int Packet::getDNSFlagsRA() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 7) & 0x0001;
}

/**
*	@brief	获取DNS首部标志Z
*	@param	-
*	@return DNS首部标志Z	-1	DNS首部为空
*/
int Packet::getDNSFlagsZ() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 4) & 0x0007;
}

/**
*	@brief	获取DNS首部标志RCODE
*	@param	-
*	@return DNS首部标志RCODE	-1	DNS首部为空
*/
int Packet::getDNSFlagsRCODE() const
{
	if (dnsh == NULL)
		return -1;
	else
		return ntohs(dnsh->flags) & 0x000F;
}
