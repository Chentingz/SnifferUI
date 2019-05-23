#include "stdafx.h"
#include "PacketPool.h"

PacketPool::PacketPool()
{
}


PacketPool::~PacketPool()
{
}

/**
*	@brief	添加数据包到池
*	@param	pkt_data	数据包	
*	@param	header		首部
*	@return	-
*/
void PacketPool::add(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if (header && pkt_data)
	{
		int pktNum = 1 + m_pkts.size();
		Packet pkt(header, pkt_data, pktNum);
		m_pkts[pktNum] = pkt;
	}
}

/**
*	@brief	添加数据包到池
*	@param	pkt	数据包
*	@return	-
*/
void PacketPool::add(const Packet &pkt)
{
	if(!pkt.isEmpty())
		m_pkts[pkt.num] = pkt;
}

/**
*	@brief	根据数据包编号，从池中删除指定数据包
*	@param	pktNum	数据包编号
*	@return	-
*/
void PacketPool::remove(int pktNum)
{
	if (pktNum < 1 || pktNum > m_pkts.size())
		return;
	m_pkts.erase(pktNum);
}

void PacketPool::clear()
{
	if (m_pkts.size() > 0)
		m_pkts.clear();
}

/**
*	@brief	根据数据包编号，从池中获取指定数据包
*	@param	pktNum	数据包编号
*	@return	pkt		数据包引用
*/
Packet& PacketPool::get(int pktNum)
{
	if (m_pkts.count(pktNum) > 0)
		return m_pkts[pktNum];
	return Packet();
}

/**
*	@brief	从池中获取最后一个数据包
*	@param	pktNum	数据包编号
*	@return	pkt		数据包引用
*/
Packet& PacketPool::getLast()
{	
	if (m_pkts.count(m_pkts.size()) > 0)
		return m_pkts[m_pkts.size()];
	return Packet();
}

/**
*	@brief	获取池子中数据包个数
*	@param	-
*	@return	数据包个数
*/
int PacketPool::getSize() const
{
	return m_pkts.size();
}

/**
*	@brief	判断池子是否为空
*	@param	-
*	@return	true 空	false 非空
*/
bool PacketPool::isEmpty() const
{
	if (m_pkts.size()) 
		return false;
	return true;
}


