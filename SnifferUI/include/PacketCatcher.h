#pragma once
#include "PacketPool.h"
#include "pcap.h"

#define WM_PKTCATCH	(WM_USER + 100)
#define WM_TEXIT	(WM_USER + 101)

const int MODE_CAPTURE_LIVE = 0;
const int MODE_CAPTURE_OFFLINE = 1;
const int READ_PACKET_TIMEOUT = 1000;

UINT capture_thread(LPVOID pParam);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 该类用于捕获数据包，并存储到数据包池、文件 */
class PacketCatcher
{
private:
	pcap_t			*m_adhandle;	// 网卡描述符
	PacketPool		*m_pool;		// 数据包池的指针
	pcap_dumper_t	*m_dumper;		// 转储文件描述符
	CString         m_dev;			// 网卡/文件信息
	pcap_if_t		*m_devlist;		// 网卡列表

public:
	PacketCatcher();
	PacketCatcher(PacketPool *pool);
	~PacketCatcher();

	bool setPool(PacketPool *pool);
	bool openAdapter(int selItemIndexOfDevList, const CTime &currentTime);
	bool openAdapter(CString path);
	bool closeAdapter();
	void startCapture(int mode);
	void stopCapture();
	CString getDevName();
	void setDevList(pcap_if_t* devlist);
};

