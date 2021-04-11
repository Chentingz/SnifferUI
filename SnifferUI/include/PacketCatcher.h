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

/* �������ڲ������ݰ������洢�����ݰ��ء��ļ� */
class PacketCatcher
{
private:
	pcap_t			*m_adhandle;	// ����������
	PacketPool		*m_pool;		// ���ݰ��ص�ָ��
	pcap_dumper_t	*m_dumper;		// ת���ļ�������
	CString         m_dev;			// ����/�ļ���Ϣ
	pcap_if_t		*m_devlist;		// �����б�

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

