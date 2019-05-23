#pragma once
#include "ProtocolHeader.h"

class Packet
{
public:
	Ethernet_Header			*ethh;			// 以太网首部
	IP_Header				*iph;			// IP首部
	ARP_Header				*arph;			// ARP首部
	ICMP_Header				*icmph;			// ICMP首部
	TCP_Header				*tcph;			// TCP首部
	UDP_Header				*udph;			// UDP首部
	DNS_Header				*dnsh;			// DNS首部
	DHCP_Header				*dhcph;			// DHCP首部
	u_char					*httpmsg;		// HTTP报文

	u_char					*pkt_data;		// 数据包（帧）
	struct pcap_pkthdr		*header;		// 捕获数据包长度，数据包长度，数据包到达时间
	u_short					num;			// 数据包编号，从1开始
	CString					protocol;		// 协议


	Packet();
	Packet(const Packet &p);
	Packet(const struct pcap_pkthdr *header, const u_char *pkt_data, const u_short &packetNum);
	Packet& operator=(const Packet	&p);
	~Packet();

	bool isEmpty() const;

	int decodeEthernet();
	int decodeIP(u_char *L2payload);
	int decodeARP(u_char *L2payload);
	int decodeICMP(u_char *L3payload);
	int decodeTCP(u_char *L3payload);
	int decodeUDP(u_char *L3payload);
	int decodeDNS(u_char *L4payload);
	int decodeDHCP(u_char *L4payload);
	int decodeHTTP(u_char *L4payload);

	int getIPHeaderLegnth() const;
	int getIPHeaderLengthRaw() const;
	int getIPFlags() const;
	int getIPFlagsMF() const;
	int getIPFlagDF() const;
	int getIPOffset() const;

	u_short getICMPID()	const;
	u_short getICMPSeq() const;

	int getTCPHeaderLength() const;
	int getTCPHeaderLengthRaw() const;
	u_short getTCPFlags()	const;
	int getTCPFlagsURG()	const;
	int getTCPFlagsACK()	const;
	int getTCPFlagsPSH()	const;
	int getTCPFlagsRST()	const;
	int getTCPFlagsSYN()	const;
	int getTCPFlagsFIN()	const;

	int getL4PayloadLength() const;

	int getDNSFlagsQR()		const;
	int getDNSFlagsOPCODE()	const;
	int getDNSFlagsAA()		const;
	int getDNSFlagsTC()		const;
	int getDNSFlagsRD()		const;
	int getDNSFlagsRA()		const;
	int getDNSFlagsZ()		const;
	int getDNSFlagsRCODE()	const;
};