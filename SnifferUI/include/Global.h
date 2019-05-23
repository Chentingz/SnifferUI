#include "pcap.h"
#include "remote-ext.h"
#include "Afxtempl.h"
#include "Packet.h"

#define PCAP_ERRBUFF_SIZE	50

/* 堆文件文件名 */
char filename[50];

/* 控件指针 */
CButton			*g_pBtnStart;
CButton			*g_pBtnPause;
CButton			*g_pBtnStop;
CButton			*g_pBtnFilter;
CButton			*g_pBtnClear;
CComboBox		*g_pComboBoxDevList;
CListCtrl		*g_pListCtrlPacketList;
CTreeCtrl		*g_pTreeCtrlPacketInfo;
CEdit			*g_pEditCtrlPacketData;
//CRichEditCtrl	*g_pRichEditCtrlFilterInput;
CComboBox		*g_pComboBoxlFilterInput;

/* 网卡信息 */
pcap_if_t *g_pAllDevs,*g_pDev;

/* pcap中已打开的捕捉实例的描述符 */
pcap_t *g_pAdhandle;

/* 堆文件 */
pcap_dumper_t *g_dumpfile;
CString g_dumpFileName;

/* 全局变量errbuf，存放错误信息 */
char g_errbuf[PCAP_ERRBUF_SIZE];



/* 数据包列表行列，编号 */
int g_listctrlPacketListRows = -1;
int g_listctrlPacketListCols = 0;
int g_listctrlPacketListCount = 0;

u_short g_packetCaptureSum = 0;

/* 链表，储存Packet类实例 */
CList<Packet, Packet> g_packetLinkList;

/* 线程入口函数 */
UINT capture_thread(LPVOID pParam);

/* 捕获处理函数 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 控件初始化 */
void initialComboBoxDevList();
void initialListCtrlPacketList();
void initialComboBoxFilterList();

/* 打印 */
int printListCtrlPacketList(const Packet &pkt);
int printListCtrlPacketList(const CList<Packet, Packet> &packetLinkList);
int printListCtrlPacketList(const CList<Packet, Packet> &packetLinkList, const CString &filter);


int	printEditCtrlPacketData(const Packet &pkt);

int printTreeCtrlPacketInfo(const Packet &pkt);
int printEthernet2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printIP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printARP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printICMP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printTCP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printUDP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printDNS2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printDHCP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printHTTP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);

/* 转换 */
CString	MACAddr2CString(const MAC_Address &addr);
CString	IPAddr2CString(const IP_Address &addr);

/* 域名转换 将规定格式的name2转换为域名name1 */
void translateNameInDNS(char *name1, const char *name2);

/* DNS资源记录数据部分转换 将带有指针c0的地址data2转换为地址data1 offset为到dns首部的偏移量*/
void translateData(const DNS_Header *dnsh, char *data1, char *data2, const int data2_len);

/* 判断data中有无指针0xc0,并返回指针在data中的位置*/
int is0xC0PointerInName(char *name);

CString getNameInDNS(char *name, const DNS_Header *pDNSHeader);
CString get0xC0PointerValue(const DNS_Header *pDNSHeader, const int offset);
int is0xC0PointerInName(char *name);