#pragma once
#include <map>
#include "Packet.h"

/* 该类管理数据包 */
class PacketPool
{
private:
	std::map<int, Packet> m_pkts;		// 存储数据包，key为数据包编号，value为数据包

public:
	PacketPool();
	~PacketPool();

	void add(const struct pcap_pkthdr *header, const u_char *pkt_data);
	void add(const Packet &pkt);
	void remove(int pktNum);
	void clear();
	Packet& get(int pktNum);
	Packet& getLast();
	int getSize() const;
	bool isEmpty() const;
};

