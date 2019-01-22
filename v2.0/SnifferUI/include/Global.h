#include "pcap.h"
#include "remote-ext.h"
#include "Afxtempl.h"
#include "Packet.h"

#define PCAP_ERRBUFF_SIZE	50

/* 堆文件文件名 */
char filename[50];

/* 控件指针 */
CWnd *g_pBtnStart;
CWnd *g_pBtnPause;
CWnd *g_pBtnStop;
CComboBox *g_pComboBoxDevList;
CListCtrl *g_pListCtrlPacketList;
CTreeCtrl *g_pTreeCtrlPacketInfo;
CEdit *g_pEditCtrlPacketData;

/* 网卡信息 */
pcap_if_t *g_pAllDevs,*g_pDev;

/* pcap抓包用到的变量 */
pcap_t *g_pAdhandle;

/* 全局变量errbuf，存放错误信息 */
char g_errbuf[PCAP_ERRBUF_SIZE];



/* 数据包列表行列，编号 */
int g_listctrlPacketListRows = -1;
int g_listctrlPacketListCols = 0;
int g_listctrlPacketListCount = 0;



/* 链表，储存报文的首部 */
//CList<packet_header, packet_header> linklist;
CList<Packet, Packet> g_packetLinkList;

/* 线程入口函数 */
UINT capture_thread(LPVOID pParam);
//UINT decode_thread(LPVOID pParam);

//typedef struct decode_Thread_pParam
//{
//	u_char*	pkt_data;
//	u_short	caplen;
//}decode_Thread_pParam;

/* 捕获处理函数 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 控件初始化 */
void initialComboBoxDevList();
void initialListCtrlPacketList();


/* 打印 */
int printListCtrlPacketList(const Packet &pkt);
int printListCtrlPacketList(const CList<Packet, Packet> &packetLinkList);


int	printEditCtrlPacketData(const Packet &pkt);

int printTreeCtrlPacketInfo(const Packet &pkt, int pktIndex);
int printEthernet2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printIP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printARP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printICMP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printTCP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
int	printUDP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
//int	printDNS2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
//int	printDHCP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);
//int	printHTTP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode);

/* 转换 */
CString	MACAddr2CString(const MAC_Address &addr);
CString	IPAddr2CString(const IP_Address &addr);






/* 存储报文首部	*/
//void saveFrame(const u_char *pkt_data, int offset);		//ok
//void saveIP(const u_char *pkt_data, int offset);		//ok
//void saveARP(const u_char *pkt_data, int offset);		//ok
//void saveUDP(const u_char *pkt_data, int offset);		//ok
//void saveTCP(const u_char *pkt_data, int offset);		//ok
//void saveICMP(const u_char *pkt_data,int offset);		//ok
//void saveDNS(const u_char *pkt_data,int offset);		//ok


/* 解析报文首部 */
//void decodeFrame(mac_address *saddr, mac_address *daddr, u_short *eth_type, HTREEITEM *hParent);
//void decodeIP(ip_header *iph,HTREEITEM *hParent);
//void decodeARP(arp_header *arph, HTREEITEM *hParent);
//void decodeUDP(udp_header *udph, HTREEITEM *hParent);
//void decodeTCP(tcp_header *tcph, HTREEITEM *hParent);
//void decodeDNS(u_char *pkt_data, int offset, dns_header *dnsh, HTREEITEM *hParent);			// offset为到dns首部的偏移量
//void decodeHTTP(u_char *pkt_data, int offset, HTREEITEM *hParent);							// offset为到HTTP报文的偏移量
//void decodeICMP(icmp_header *icmph, HTREEITEM *hParent);		
//void decodeDHCP(u_char *pkt_data, int offset, HTREEITEM *hParent);							// offset为到DHCP报文的偏移量


///* 域名转换 将规定格式的name2转换为域名name1 */
//void translateName(char *name1, const char *name2);
//
///* DNS资源记录数据部分转换 将带有指针c0的地址data2转换为地址data1 offset为到dns首部的偏移量*/
//void translateData(u_char *pkt_data, int offset, char *data1, char *data2, int data2_len);
//
///* 判断data中有无指针0xc0,并返回指针在data中的位置*/
//int isNamePtr(char *data);
