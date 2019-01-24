#pragma once
#include "ProtocolHeader.h"

class Packet
{
public:
	Ethernet_Header			*ethh;			// 以太网首部
	IP_Header				*iph;			// ip首部
	ARP_Header				*arph;			// arp首部
	ICMP_Header				*icmph;			// icmp首部
	TCP_Header				*tcph;			// tcp首部
	UDP_Header				*udph;			// udp首部
	DNS_Header				*dnsh;			// dns首部
	DHCP_Header				*dhcph;			// dhcp首部
	u_char					*httpmsg;		// http报文

	u_char					*pkt_data;		// 数据包（帧）
	struct pcap_pkthdr		*header;		// 捕获数据包长度，数据包长度，数据包到达时间
	CString					protocol;		// 协议

	Packet();
	Packet(const Packet &p);
	Packet(const u_char *pkt_data, const struct pcap_pkthdr *header);
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

	int getL4PayloadLength() const;
};