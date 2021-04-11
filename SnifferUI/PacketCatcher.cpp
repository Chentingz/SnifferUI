#include "stdafx.h"
#include "PacketCatcher.h"
#include "Packet.h"
#include "ThreadParam.h"
#define HAVE_REMOTE
#include "pcap.h"

PacketCatcher::PacketCatcher()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
	m_devlist = NULL;
}

PacketCatcher::PacketCatcher(PacketPool * pool)
{
	m_adhandle = NULL;
	m_pool = pool;
	m_dumper = NULL;
	m_devlist = NULL;
}


PacketCatcher::~PacketCatcher()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
	if (m_devlist)
	{
		pcap_freealldevs(m_devlist); 
		m_devlist = NULL;
	}
		
}

bool PacketCatcher::setPool(PacketPool *pool)
{
	if (pool)
	{
		m_pool = pool;
		return true;
	}
	return false;
}

/**
*	@brief	打开指定网卡，获得网卡描述符adhandle
*	@param	selItemIndexOfDevList	网卡列表选中项的下标
*	@return true	打开成功	false	打开失败
*/
bool PacketCatcher::openAdapter(int selItemIndexOfDevList, const CTime &currentTime)
{
	if (selItemIndexOfDevList < 0 || m_adhandle)
		return false;

	int count = 0, selDevIndex = selItemIndexOfDevList - 1;
	//pcap_if_t *dev, *allDevs;
	//char errbuf[PCAP_ERRBUF_SIZE + 1];
	//if (pcap_findalldevs(&allDevs, errbuf) == -1)
	//{
	//	AfxMessageBox(_T("pcap_findalldevs错误!"), MB_OK);
	//	return false;
	//}
	//for (dev = allDevs; count < selDevIndex; dev = dev->next, ++count);
	pcap_if_t* dev;
	for (dev = m_devlist; count < selDevIndex; dev = dev->next, ++count);
	// 网卡信息拷贝
	m_dev = dev->description + CString(" ( ") + dev->name + " )";

	// 打开网卡
	if ((m_adhandle = pcap_open_live(dev->name,
		65535,						// 最大捕获长度
		PCAP_OPENFLAG_PROMISCUOUS,	// 设置网卡为混杂模式 
		READ_PACKET_TIMEOUT,		// 读取超时时间
		NULL)) == NULL)
	{
		AfxMessageBox(_T("pcap_open_live错误!"), MB_OK);
		return false;
	}

	/* 打开转储文件 */
	CString file = "SnifferUI_" + currentTime.Format("%Y%m%d%H%M%S") + ".pcap";
	CString path = ".\\tmp\\" + file;
	m_dumper = pcap_dump_open(m_adhandle, path);

	//pcap_freealldevs(allDevs);
	return true;
}

/**
*	@brief	打开指定文件，获得文件描述符adhandle
*	@param	path	文件路径
*	@return true	打开成功	false	打开失败
*/
bool PacketCatcher::openAdapter(CString path)
{
	if (path.IsEmpty())
		return false;
	m_dev = path;
	if ( (m_adhandle = pcap_open_offline(path, NULL))  == NULL)
	{
		AfxMessageBox(_T("pcap_open_offline错误!"), MB_OK);
		return false;
	}
	return true;
}

/**
*	@brief	关闭已打开网卡
*	@param	-
*	@return true	关闭成功	false	关闭失败
*/
bool PacketCatcher::closeAdapter()
{
	if (m_adhandle)
	{
		pcap_close(m_adhandle);
		m_adhandle = NULL;
		if (m_dumper)
		{
			pcap_dump_close(m_dumper);
			m_dumper = NULL;
		}
		return true;
	}
	return false;
}

/**
*	@brief	开始抓包
*	@param	-
*	@return -
*/
void PacketCatcher::startCapture(int mode)
{
	if (m_adhandle && m_pool)
		AfxBeginThread(capture_thread, new ThreadParam(m_adhandle, m_pool, m_dumper, mode));
}

/**
*	@brief	停止抓包
*	@param	-
*	@return -
*/
void PacketCatcher::stopCapture()
{
	if (m_adhandle)
		pcap_breakloop(m_adhandle);
}

CString PacketCatcher::getDevName()
{
	return m_dev;
}

void PacketCatcher::setDevList(pcap_if_t *devlist)
{
	m_devlist = devlist;
}


/**
*	@brief 捕获数据包线程入口函数，全局函数
*	@param pParam 传入线程的参数
*	@return 0 表示抓包成功	-1 表示抓包失败
*/
UINT capture_thread(LPVOID pParam)
{
	ThreadParam *p = (ThreadParam*)pParam;

	/* 开始捕获数据包 */
	pcap_loop(p->m_adhandle, -1, packet_handler, (unsigned char *)p);
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_TEXIT, NULL, NULL);
	return 0;
}

/**
*	@brief	捕获数据包处理函数，全局回调函数
*	@param	param		自定义参数
*	@param	header		数据包首部
*	@param	pkt_data	数据包（帧）
*	@return
*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ThreadParam *threadParam = (ThreadParam *)param;
	// 根据捕获模式抓包
	switch (threadParam->m_mode)
	{
	case MODE_CAPTURE_LIVE:
	{		
		threadParam->m_pool->add(header, pkt_data);
		pcap_dump((u_char*)threadParam->m_dumper, header, pkt_data);
		break;
	}
	case MODE_CAPTURE_OFFLINE:
	{
		threadParam->m_pool->add(header, pkt_data);
		break;
	}
	}

	// 发送消息给主窗口SnifferUIDlg
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_PKTCATCH, NULL, (LPARAM)(threadParam->m_pool->getLast().num));

	// 若是在线抓包，则让线程睡眠0.5秒，防止界面卡顿
	if (threadParam->m_mode == MODE_CAPTURE_LIVE) {
		Sleep(500);
	}
}
