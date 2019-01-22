#include "pcap.h"
#include "remote-ext.h"
#include "Afxtempl.h"

#define PCAP_ERRBUFF_SIZE	50


/* 堆文件文件名 */
char filename[50];

/* 全局变量控件 */
CListCtrl *pList1;
CComboBox *pDevList;
CWnd *pStart;
CWnd *pStop;
CTreeCtrl *pTree;


/* 全局变量，存放设备信息 */
pcap_if_t *alldevs,*d;

/* 全局变量errbuf，存放错误信息 */
char errbuf[PCAP_ERRBUF_SIZE];

/* 全局变量adhandle */
pcap_t *adhandle;

/* 设备列表行列，编号 */
int list_rows = -1;
int list_cols = 0;
int list_count = 0;

/* 链表，储存报文的首部 */
CList<packet_header, packet_header> linklist;

/* 线程处理函数 */
UINT capture_thread(LPVOID pParam);

/* 捕获处理函数 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 存储报文首部	*/
void saveFrame(const u_char *pkt_data, int offset);		//ok
void saveIP(const u_char *pkt_data, int offset);		//ok
void saveARP(const u_char *pkt_data, int offset);		//ok
void saveUDP(const u_char *pkt_data, int offset);		//ok
void saveTCP(const u_char *pkt_data, int offset);		//ok
void saveICMP(const u_char *pkt_data,int offset);		//ok
void saveDNS(const u_char *pkt_data,int offset);		//ok


/* 解析报文首部 */
void decodeFrame(mac_address *saddr, mac_address *daddr, u_short *eth_type, HTREEITEM *hParent);
void decodeIP(ip_header *iph,HTREEITEM *hParent);
void decodeARP(arp_header *arph, HTREEITEM *hParent);
void decodeUDP(udp_header *udph, HTREEITEM *hParent);
void decodeTCP(tcp_header *tcph, HTREEITEM *hParent);
void decodeDNS(u_char *pkt_data, int offset, dns_header *dnsh, HTREEITEM *hParent);			// offset为到dns首部的偏移量
void decodeHTTP(u_char *pkt_data, int offset, HTREEITEM *hParent);							// offset为到HTTP报文的偏移量
void decodeICMP(icmp_header *icmph, HTREEITEM *hParent);		
void decodeDHCP(u_char *pkt_data, int offset, HTREEITEM *hParent);							// offset为到DHCP报文的偏移量


/* 域名转换 将规定格式的name2转换为域名name1 */
void translateName(char *name1, const char *name2);

/* DNS资源记录数据部分转换 将带有指针c0的地址data2转换为地址data1 offset为到dns首部的偏移量*/
void translateData(u_char *pkt_data, int offset, char *data1, char *data2, int data2_len);

/* 判断data中有无指针0xc0,并返回指针在data中的位置*/
int isNamePtr(char *data);
