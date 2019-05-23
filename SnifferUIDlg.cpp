// SnifferUIDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SnifferUI.h"
#include "SnifferUIDlg.h"

#include "packet_header.h"
#include "var_func.h"
#include "string.h"
#include "ctype.h"
//#include "remote-ext.h"

//#include "winsock2.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIDlg dialog

CSnifferUIDlg::CSnifferUIDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSnifferUIDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CSnifferUIDlg)
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSnifferUIDlg)
	DDX_Control(pDX, IDC_TREE1, m_tree);
	DDX_Control(pDX, IDC_STOP, m_stop);
	DDX_Control(pDX, IDC_START, m_start);
	DDX_Control(pDX, IDC_LIST1, m_listctl1);
	DDX_Control(pDX, IDC_COMBO1, m_devlist);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CSnifferUIDlg, CDialog)
	//{{AFX_MSG_MAP(CSnifferUIDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, OnStart)
	ON_BN_CLICKED(IDC_STOP, OnStop)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, OnClickList1)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIDlg message handlers

BOOL CSnifferUIDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here

	/* 初始化 */
	pList1 = &m_listctl1;											  // 输出列表控件的指针
	pTree = &m_tree;

	DWORD dwStyle = m_listctl1.GetExtendedStyle();                    // 添加列表框的网格线
    dwStyle |= LVS_EX_FULLROWSELECT;            
    dwStyle |= LVS_EX_GRIDLINES;                
    m_listctl1.SetExtendedStyle(dwStyle);
	/* 设备列表标题	*/
	m_listctl1.InsertColumn(0,"编号",LVCFMT_LEFT,40);
	m_listctl1.InsertColumn(1,"时间",LVCFMT_LEFT,180);
	m_listctl1.InsertColumn(2,"长度",LVCFMT_LEFT,50);
	m_listctl1.InsertColumn(3,"源MAC地址",LVCFMT_LEFT,180);
	m_listctl1.InsertColumn(4,"目的MAC地址",LVCFMT_LEFT,180);
	m_listctl1.InsertColumn(5,"源IP地址",LVCFMT_LEFT,120);
	m_listctl1.InsertColumn(6,"目的IP地址",LVCFMT_LEFT,120);
	m_listctl1.InsertColumn(7,"协议",LVCFMT_LEFT,50);

	
	/*
	*	获取设备列表
	*/

    /* 获取本地机器设备列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

	/* 打印设备描述到列表框中 */
    for(d= alldevs; d != NULL; d= d->next)
    {
        if (d->description)
			
			m_devlist.AddString(d->description);
    }
	
	/* 链表 */
	/*
	link = (pkth_linklist*)malloc(sizeof(pkth_linklist));
	link->next = NULL;
	pTail = link;
	*/





	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CSnifferUIDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSnifferUIDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CSnifferUIDlg::OnQueryDragIcon()
{

	return (HCURSOR) m_hIcon;
}


void CSnifferUIDlg::OnStop() 
{
	// TODO: Add your control notification handler code here

	pStart = GetDlgItem(IDC_START);
	pStop = GetDlgItem(IDC_STOP);

	pStop->EnableWindow(FALSE);
	pStart->EnableWindow(TRUE);

	/* 停止抓包 */
	pcap_breakloop(adhandle);
	
}

void CSnifferUIDlg::OnStart() 
{
	// TODO: Add your control notification handler code here

	pStart = GetDlgItem(IDC_START);
	pStop = GetDlgItem(IDC_STOP);
	pDevList = (CComboBox*)GetDlgItem(IDC_COMBO1);

	pStart->EnableWindow(FALSE);
	pStop->EnableWindow(TRUE);
	
	/* 创建线程 */
	myWinThread = AfxBeginThread(capture_thread, NULL, 0, NULL, 0, NULL);
}




/* 线程处理函数 */
UINT capture_thread(LPVOID pParam)
{
	/* 获取选中的设备 */

	HWND mHwnd = AfxGetMainWnd()->m_hWnd;
	if(mHwnd == NULL)
	{
		AfxMessageBox(_T("获取窗口句柄失败"),MB_OK);
		return -1;
	}

	int sel_index = pDevList->GetCurSel();			//获取选中设备的索引
	if(sel_index == CB_ERR)
	{
		AfxMessageBox(_T("没有选中项"),MB_OK);
		return -1;
	}
		
	int count = 0;
    for(d= alldevs; count < sel_index; d = d->next,count++);


	/* 打开指定设备 */
	if((adhandle = pcap_open_live(d->name,
					65535,
					 PCAP_OPENFLAG_PROMISCUOUS,
					1000,
					errbuf)) == NULL)
	{ 
		AfxMessageBox(_T("pcap_open_live错误!"), MB_OK);
	}

	/* 判断接口的链路层类型是否为以太网*/
	if( pcap_datalink(adhandle) != DLT_EN10MB)
		AfxMessageBox(_T("数据链路层不是以太网"), MB_OK);

	
	pcap_dumper_t *dumpfile;	
	/* 打开堆文件
	strcpy(filename, "pkt_cap");

	dumpfile = pcap_dump_open(adhandle, filename);
	*/

	/*	开始捕获数据包 */
//	AfxMessageBox(_T("开始抓包"), MB_OK);
	pcap_loop(adhandle, -1,	packet_handler, (unsigned char *)dumpfile);
//	AfxMessageBox(_T("结束抓包"), MB_OK);
	
	return 0;

}


/* 捕获处理函数 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* 写入堆文件 */
//	pcap_dump(dumpfile, header, pkt_data);


	/* 日志文件 */
	
	char *path = "E:\\Code\\Sniffer\\pkt_cap_log.txt";
	FILE *save_file;
	save_file = fopen(path,"a");	//以追加形式写入
	

	/* 编号 */
	char str_count[4]; 
	itoa(++list_count, str_count, 10);								// 将编号由整形转换为字符串
	pList1->InsertItem(++list_rows, str_count);

	
	fprintf(save_file, "%d ", list_count);
	fprintf(save_file, " / ");
	
	
	/* 时间 */
	//header->ts.
	char * pkt_time = ctime((time_t*)&((header->ts).tv_sec));
	pList1->SetItemText(list_rows, ++list_cols, pkt_time);

	
	fprintf(save_file, "%s", pkt_time);
	fprintf(save_file, " / ");
	

	/* 长度 */
	char str_caplen[6];
	itoa(header->caplen, str_caplen, 10);
	pList1->SetItemText(list_rows, ++list_cols, str_caplen);

	
	fprintf(save_file, "len: ");
	fprintf(save_file, "%s ", str_caplen);
	fprintf(save_file, " / ");
	

	/* 源mac*/
	mac_address *src_mac = (mac_address*)(pkt_data + 6);
	/* 输出到界面上 */
	CString str_srcmac;
	str_srcmac.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), src_mac->byte1, src_mac->byte2, src_mac->byte3, src_mac->byte4, src_mac->byte5, src_mac->byte6);
	pList1->SetItemText(list_rows, ++list_cols, str_srcmac);



	/* 输出到日志文件中  */
	
	fprintf(save_file, "src_mac: ");
	fprintf(save_file,"%s", str_srcmac);
	fprintf(save_file, " / ");
	


	/* 目的mac */

	mac_address *dst_mac = (mac_address*)(pkt_data);
		/* 输出到界面上 */
	CString str_dstmac;
	str_dstmac.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), dst_mac->byte1, dst_mac->byte2, dst_mac->byte3, dst_mac->byte4, dst_mac->byte5, dst_mac->byte6);
	pList1->SetItemText(list_rows, ++list_cols, str_dstmac); 

		/* 输出到日志文件中 */
	
	fprintf(save_file, "dst_mac: ");
	fprintf(save_file,"%s", str_dstmac);
	fprintf(save_file, " / ");
	

		


	/* 源目IP */
	if(ntohs(*(u_short*)(pkt_data + 12)) == 0x0800)
	{
		ip_header *ip_hdr = (ip_header*)(pkt_data + 14);
		ip_address *src_ip = &ip_hdr->srcaddr;
		ip_address *dst_ip = &ip_hdr->dstaddr;

		
		/* 输出到界面上 */
		CString str_srcip;
		str_srcip.Format(_T("%d.%d.%d.%d"), src_ip->byte1, src_ip->byte2, src_ip->byte3, src_ip->byte4);
		pList1->SetItemText(list_rows, ++list_cols, str_srcip);
	
		CString str_dstip;
		str_dstip.Format(_T("%d.%d.%d.%d"), dst_ip->byte1, dst_ip->byte2, dst_ip->byte3, dst_ip->byte4);
		pList1->SetItemText(list_rows, ++list_cols, str_dstip);

		/* 输出到日志文件中 */
		
		fprintf(save_file, "src_ip: ");
		fprintf(save_file, str_srcip);
		fprintf(save_file, " / ");
		
		fprintf(save_file, "dst_ip: ");
		fprintf(save_file, str_dstip);
		fprintf(save_file, "\r\n");
		
	}
	else if(ntohs(*(u_short*)(pkt_data + 12)) == 0x0806)
	{
		arp_header *arp_hdr = (arp_header*)(pkt_data + 14);
		ip_address *src_ip = &arp_hdr->srcip;
		ip_address *dst_ip = &arp_hdr->dstip;

		/* 输出到界面上 */
		CString str_srcip;
		str_srcip.Format(_T("%d.%d.%d.%d"), src_ip->byte1, src_ip->byte2, src_ip->byte3, src_ip->byte4);
		pList1->SetItemText(list_rows, ++list_cols, str_srcip);
	
		CString str_dstip;
		str_dstip.Format(_T("%d.%d.%d.%d"), dst_ip->byte1, dst_ip->byte2, dst_ip->byte3, dst_ip->byte4);
		pList1->SetItemText(list_rows, ++list_cols, str_dstip);

		/* 输出到日志文件中 */
		
		fprintf(save_file, "src_ip: ");
		fprintf(save_file, str_srcip);
		fprintf(save_file, " / ");
		
		fprintf(save_file, "dst_ip: ");
		fprintf(save_file, str_dstip);
		fprintf(save_file, "\r\n");

	}


	/* 存储完整数据包 */
	packet_header pkth;

	/* 初始化 */
	pkth.arph = NULL;
	pkth.iph  = NULL;
	pkth.icmph = NULL;
	pkth.udph = NULL;
	pkth.tcph = NULL;
	pkth.dnsh = NULL;

	u_char *pkt_data1 = (u_char*)malloc(header->caplen);

	memcpy(pkt_data1, pkt_data, header->caplen);	

	pkth.pkt_data = pkt_data1;
	pkth.caplen = header->caplen;

	linklist.AddTail(pkth);
	


	/* 存储以太网帧 */
	saveFrame(pkt_data, 0);


	fclose(save_file);

	/* 列复位 */
	list_cols = 0;

}	

/* 存储以太网帧 */
void saveFrame(const u_char *pkt_data, int offset)
{
	/* 获取以太网帧的类型字段、源目MAC地址 */
	u_short eth_type = ntohs(*(u_short*)(pkt_data + 12));
	mac_address *src_mac = (mac_address*)(pkt_data + 6);
	mac_address *dst_mac = (mac_address*)(pkt_data);
	
	/* 将类型、源目MAC地址保存到链表的尾结点上 */
	linklist.GetTail().saddr = *src_mac;
	linklist.GetTail().daddr = *dst_mac;
	linklist.GetTail().eth_type = eth_type;
	
	/* 根据以太网帧中类型字段存储报文 */
	switch(eth_type)
	{
	case 0x0800: saveIP(pkt_data, 14); 
					break;
	case 0x0806: saveARP(pkt_data, 14); 
					pList1->SetItemText(list_rows, ++list_cols, "ARP"); 
					break;
	default: break;
	}
	
}

/* 存储IP包 */
void saveIP(const u_char *pkt_data, int offset)				//offset为ip首部距离pkt_data的偏移量
{
	ip_header *ip_hdr = (ip_header*)(pkt_data + offset);

	/* 存储ip首部到链表中 */
	ip_header *p ;

	p = (ip_header*)malloc(sizeof(ip_header));
	p->ver_hrdlen = ip_hdr->ver_hrdlen;
	p->tos = ip_hdr->tos;
	p->totallen = ip_hdr->totallen;
	p->identifier = ip_hdr->identifier;
	p->flags_offset = ip_hdr->flags_offset;
	p->ttl = ip_hdr->ttl;
	p->proto = ip_hdr->proto;
	p->checksum = ip_hdr->checksum;
	p->option_padding = ip_hdr->option_padding;
	p->srcaddr = ip_hdr->srcaddr;
	p->dstaddr = ip_hdr->dstaddr;

	linklist.GetTail().iph = p;

	/* 根据上层协议存储报文首部 */
	switch(ip_hdr->proto)
	{
	case 1:		saveICMP(pkt_data, offset + (ip_hdr->ver_hrdlen & 0x0f) * 4);
				pList1->SetItemText(list_rows, ++list_cols, "ICMP"); 
				break;	//ICMP

	case 6:		saveTCP(pkt_data, offset + (ip_hdr->ver_hrdlen & 0x0f) * 4); 
				break;	//TCP

	case 17:	saveUDP(pkt_data, offset + (ip_hdr->ver_hrdlen & 0x0f) * 4); 
				break;	//UDP

	default:	pList1->SetItemText(list_rows, ++list_cols, "IPv4"); 
				break;
	}
}


/* 存储ARP包 */
void saveARP(const u_char *pkt_data, int offset)				//offset为ARP首部距离pkt_data的偏移量
{
	arp_header *arp_hdr = (arp_header*)(pkt_data + offset);

	/* 存储arp首部到链表中 */
	arp_header *p;

	p = (arp_header*)malloc(sizeof(arp_header));
	p->hardtype = arp_hdr->hardtype;
	p->prototype = arp_hdr->prototype;
	p->hardlen = arp_hdr->hardlen;
	p->protolen = arp_hdr->protolen;
	p->op = arp_hdr->op;
	p->srcmac = arp_hdr->srcmac;
	p->srcip = arp_hdr->srcip;
	p->dstmac = arp_hdr->dstmac;
	p->dstip = arp_hdr->dstip;

	linklist.GetTail().arph = p;
	
}

/* 存储ICMP包*/
void saveICMP(const u_char *pkt_data,int offset)
{
	icmp_header *icmp_hdr = (icmp_header*)(pkt_data + offset);

	/* 存储icmp首部到链表中*/
	icmp_header *p;

	p = (icmp_header*)malloc(sizeof(icmp_header));
	p->type = icmp_hdr->type;
	p->code = icmp_hdr->code;
	p->chksum = icmp_hdr->chksum;
	p->others = icmp_hdr->others;

	linklist.GetTail().icmph = p;
}





/* 存储UDP包 */
void saveUDP(const u_char *pkt_data, int offset)				//offset为UDP首部距离pkt_data的偏移量
{
	udp_header *udp_hdr = (udp_header*)(pkt_data + offset);

	/* 存储udp首部到链表中 */
	udp_header* p;

	p = (udp_header*)malloc(sizeof(udp_header));
	p->srcport = udp_hdr->srcport;
	p->dstport = udp_hdr->dstport;
	p->len = udp_hdr->len;
	p->checksum = udp_hdr->checksum;

	linklist.GetTail().udph = p;

	/* 根据源目端口号存储报文首部 */
	if(ntohs(udp_hdr->srcport) == 53 || ntohs(udp_hdr->dstport) == 53)
	{
		saveDNS(pkt_data, offset + 8);
		pList1->SetItemText(list_rows, ++list_cols, "DNS"); 
	}
	else if( (ntohs(udp_hdr->srcport) == 67 && ntohs(udp_hdr->dstport) == 68) || (ntohs(udp_hdr->srcport) == 68 && ntohs(udp_hdr->dstport) == 67))
	{
		pList1->SetItemText(list_rows, ++list_cols, "DHCP"); 
	}

	else
	{
		pList1->SetItemText(list_rows, ++list_cols, "UDP"); 
	}
}

/* 存储TCP包 */
void saveTCP(const u_char *pkt_data, int offset)
{
	tcp_header *tcp_hdr = (tcp_header*)(pkt_data + offset);

	/* 存储tcp首部到链表中*/
	tcp_header *p;

	p = (tcp_header*)malloc(sizeof(tcp_header));
	p->srcport = tcp_hdr->srcport;
	p->dstport = tcp_hdr->dstport;
	p->seq = tcp_hdr->seq;
	p->ack = tcp_hdr->ack;
	p->hdrlen_rsv_flags = tcp_hdr->hdrlen_rsv_flags;
	p->win_size = tcp_hdr->win_size;
	p->chksum = tcp_hdr->chksum;
	p->urg_ptr = tcp_hdr->urg_ptr;
	p->option = tcp_hdr->option;

	linklist.GetTail().tcph = p;

	/* 根据源目端口号存储报文首部 */
	if(ntohs(tcp_hdr->srcport) == 53 || ntohs(tcp_hdr->dstport) == 53)
	{
		saveDNS(pkt_data, offset + (ntohs(tcp_hdr->hdrlen_rsv_flags) >> 12) * 4);
		pList1->SetItemText(list_rows, ++list_cols, "DNS"); 
	}

	else if(ntohs(tcp_hdr->srcport) == 80 || ntohs(tcp_hdr->dstport) == 80)
	{	
		pList1->SetItemText(list_rows, ++list_cols, "HTTP"); 
	}

	else
	{
		pList1->SetItemText(list_rows, ++list_cols, "TCP"); 
	}
	
}

/* 存储DNS */
void saveDNS(const u_char *pkt_data, int offset)
{
	dns_header *dns_hdr = (dns_header*)(pkt_data + offset);

	/* 存储dns首部到链表中 */
	dns_header *p;
	p = (dns_header*)malloc(sizeof(dns_header));
	p->identifier = dns_hdr->identifier;
	p->flags = dns_hdr->flags;
	p->questions = dns_hdr->questions;
	p->answers = dns_hdr->answers;
	p->authority = dns_hdr->authority;
	p->additional = dns_hdr->additional;

	linklist.GetTail().dnsh = p;
}

/* 解析以太网帧 */
void decodeFrame(mac_address *saddr, mac_address *daddr, u_short *eth_type, HTREEITEM *hParent)
{
	HTREEITEM hFrameItem;		//树形控件结点
	CString str1, str2;

	str1 = "以太网帧 （";
	str2.Format("%02X-%02X-%02X-%02X-%02X-%02X", saddr->byte1, saddr->byte2, saddr->byte3, saddr->byte4, saddr->byte5, saddr->byte6);
	str1 += str2 + " -> ";
	str2.Format("%02X-%02X-%02X-%02X-%02X-%02X", daddr->byte1, daddr->byte2, daddr->byte3, daddr->byte4, daddr->byte5, daddr->byte6);
	str1 += str2 + "）";
	hFrameItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);
	
	
	str1 = "源mac地址：";
	str2.Format("%02X-%02X-%02X-%02X-%02X-%02X", saddr->byte1, saddr->byte2, saddr->byte3, saddr->byte4, saddr->byte5, saddr->byte6);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hFrameItem, 0);

	str1 = "目的mac地址：";
	str2.Format("%02X-%02X-%02X-%02X-%02X-%02X", daddr->byte1, daddr->byte2, daddr->byte3, daddr->byte4, daddr->byte5, daddr->byte6);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hFrameItem, 0);

	str1 = "类型：";
	switch(*eth_type)
	{
	case 0x0800: str2 = "IPv4 (0x0800)"; break;
	case 0x0806: str2 = "ARP (0x0806)"; break;
	default: str2.Format("Unknown(0x%04hx)", *eth_type);	break;
	}
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hFrameItem, 0);

}

/* 解析IP  */
void decodeIP(ip_header *iph,HTREEITEM *hParent)
{
		HTREEITEM hIPItem;		//树形控件结点
		CString str1, str2;

		str1 = "IP （";
		str2.Format("%d.%d.%d.%d", iph->srcaddr.byte1, iph->srcaddr.byte2, iph->srcaddr.byte3, iph->srcaddr.byte4);
		str1 += str2 + " -> ";
		str2.Format("%d.%d.%d.%d", iph->dstaddr.byte1, iph->dstaddr.byte2, iph->dstaddr.byte3, iph->dstaddr.byte4);
		str1 += str2 + "）";
		hIPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

		str1 = "版本号：";
		str2.Format("%d", iph->ver_hrdlen >> 4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

		str1 = "首部长度：";
		str2.Format("%d (bytes)", (iph->ver_hrdlen & 0x0f) * 4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

		str1 = "服务质量：";
		str2.Format("0x%02x", iph->tos);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0 ,hIPItem, 0);

		str1 = "总长度： ";
		str2.Format("%hu", ntohs(iph->totallen));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0 ,hIPItem, 0);

		str1 = "标识：";
		str2.Format("0x%04hx(%hu)", ntohs(iph->identifier), ntohs(iph->identifier));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0 ,hIPItem, 0);
			

		str1 = "标志：";
		str2.Format("0x%02x", ntohs(iph->flags_offset) >> 13);
		str1 += str2;
		HTREEITEM hIPFlag = pTree->InsertItem(str1, 0, 0 ,hIPItem, 0);

		str1 = "RSV（保留位）：0";
		pTree->InsertItem(str1, 0, 0, hIPFlag, 0);

		str1 = "MF：";
		str2.Format("%d", (ntohs(iph->flags_offset) >> 14) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPFlag, 0);

		str1 = "DF：";
		str2.Format("%d", (ntohs(iph->flags_offset) >> 13) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPFlag, 0);


		
		
		str1 = "片偏移：";
		str2.Format("%d", ntohs(iph->flags_offset) & 0x1fff);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0 ,hIPItem, 0);

		str1 = "TTL：";
		str2.Format("%u", iph->ttl);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

		str1 = "协议：";
		switch(iph->proto)
		{
		case 1:	str2 = "ICMP (1)"; break;
		case 6:	str2 = "TCP (6)"; break;
		case 17: str2 = "UDP (17)"; break;
		default: str2.Format("UNKNOWN(%d)", iph->proto);	break;
		}

		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

		str1 = "校验和：";
		str2.Format("0x%02hx", ntohs(iph->checksum));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

		str1 = "源ip地址：";
		str2.Format("%d.%d.%d.%d", iph->srcaddr.byte1, iph->srcaddr.byte2, iph->srcaddr.byte3, iph->srcaddr.byte4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

		str1 = "目的ip地址：";
		str2.Format("%d.%d.%d.%d", iph->dstaddr.byte1, iph->dstaddr.byte2, iph->dstaddr.byte3, iph->dstaddr.byte4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hIPItem, 0);

}

/* 解析ARP */
void decodeARP(arp_header *arph, HTREEITEM *hParent)
{
	HTREEITEM hARPItem;			//树形控件结点
	CString str1, str2;

	str1 = "ARP （";
		switch(ntohs(arph->op))
		{
		case 1:	str2.Format("Request"); break;
		case 2:	str2.Format("Reply");	break;
		}
		str1 += str2 + "）";		
		hARPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

		str1 = "硬件类型：";
		str2.Format("%hu", ntohs(arph->hardtype), ntohs(arph->hardtype));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "协议类型：";
		str2.Format("0x%04hx (%hu)", ntohs(arph->prototype), ntohs(arph->prototype));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "硬件地址长度：";
		str2.Format("%u", arph->hardlen);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "协议地址长度：";
		str2.Format("%u", arph->protolen);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "OP：";
		switch(ntohs(arph->op))
		{
		case 1:	str2.Format("0x%04hx (Request)", ntohs(arph->op)); break;
		case 2:	str2.Format("0x%04hx (Reply)", ntohs(arph->op));	break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "源mac地址：";
		str2.Format("%02X-%02X-%02X-%02X-%02X-%02X", arph->srcmac.byte1, arph->srcmac.byte2, arph->srcmac.byte3, arph->srcmac.byte4, arph->srcmac.byte5, arph->srcmac.byte1);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "源ip地址：";
		str2.Format("%d.%d.%d.%d", arph->srcip.byte1, arph->srcip.byte2, arph->srcip.byte3, arph->srcip.byte4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);
		
		str1 = "目的mac地址：";
		str2.Format("%02X-%02X-%02X-%02X-%02X-%02X", arph->dstmac.byte1, arph->dstmac.byte2, arph->dstmac.byte3, arph->dstmac.byte4, arph->dstmac.byte5, arph->dstmac.byte1);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

		str1 = "目的ip地址：";
		str2.Format("%d.%d.%d.%d", arph->dstip.byte1, arph->dstip.byte2, arph->dstip.byte3, arph->dstip.byte4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hARPItem, 0);

}

/* 解析ICMP */
void decodeICMP(icmp_header *icmph, HTREEITEM *hParent)
{
	HTREEITEM hICMPItem;
	CString str1, str2;

	str1 = "ICMP （";

	switch(icmph->type)
	{
		case 0: str2 = "回应应答报告"; break;
		case 3: str2 = "信宿不可达报告"; break;
		case 4: str2 = "源端抑制报告"; break;
		case 5: str2 = "重定向报告"; break;
		case 8: str2 = "回应请求报告"; break;
		case 9: str2 = "路由器通告报告"; break;
		case 10: str2 = "路由器询问报告"; break;
		case 11: str2 = "超时报告"; break;
		case 12: str2 = "数据报参数错误报告"; break;
		case 13: str2 = "时间戳请求报告"; break;
		case 14: str2 = "时间戳应答报告"; break;
		case 17: str2 = "地址掩码请求报告"; break;
		case 18: str2 = "地址掩码应答报告"; break;
		default: str2.Format("UNKNOWN（%d）", icmph->type); break;
	}

	str1 += str2 + "）";

	hICMPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

	ip_address *addr = (ip_address*)(&(icmph->others));

	u_short id = (u_short)(ntohl(icmph->others) >> 16);
	u_short seq = (u_short)(ntohl(icmph->others) & 0x0000ffff);

	str1 = "类型：";
	switch(icmph->type)
	{
	case 3: str2 = "3"; 
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "代码：";
			switch(icmph->code)
			{
			case 0: str2 = "0 （网络不可达）"; break;
			case 1: str2 = "1 （主机不可达）"; break;
			case 2: str2 = "2 （协议不可达）"; break;
			case 3: str2 = "3 （端口不可达）"; break;
			case 6: str2 = "6 （信宿网络未知）"; break;
			case 7: str2 = "7 （信宿主机未知）"; break;
			default: str2.Format("%d （UNKNOWN）", icmph->code); break;
			}
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "校验和：";
			str2.Format("0x%04hx", ntohs(icmph->chksum));
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			break;

	case 4: str2 = "4";
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "代码：0 ";
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);
			
			str1 = "校验和：";
			str2.Format("0x%04hx", ntohs(icmph->chksum));
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);
			break;

	case 5: str2 = "5";
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "代码：";
			switch(icmph->code)
			{
			case 0:	str2 = "0 （对特定网络重定向）"; break;
			case 1: str2 = "1 （对特定主机重定向）"; break;
			case 2: str2 = "2 （基于指定的服务类型对特定网络重定向）";break;
			case 3: str2 = "3 （基于指定的服务类型对特定主机重定向）"; break;
			}
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "校验和：";
			str2.Format("0x%04hx", ntohs(icmph->chksum));
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);


			str1 = "目标路由器的IP地址：";
			str2.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);
			break;

	case 11: str2 = "11"; 
			 str1 += str2;
			 pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			 str1 = "代码：";
			 switch(icmph->code)
			 {
			 case 0: str2 = "0 （TTL超时）";	break;
			 case 1: str2 = "1 （分片重组超时）"; break;
			 }
			 str1 += str2;
			 pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "校验和：";
			str2.Format("0x%04hx", ntohs(icmph->chksum));
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			 break;

	case 8: str2 = "8";
			 str1 += str2;
			 pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "代码：0";
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "校验和：";
			str2.Format("0x%04hx", ntohs(icmph->chksum));
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "标识：";
			str2.Format("%hu", id);
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "序号：";
			str2.Format("%hu", seq);
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			break;

	case 0:	str2 = "0";
			str1 += str2;
		    pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "代码：0";
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "校验和：";
			str2.Format("0x%04hx", ntohs(icmph->chksum));
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "标识：";
			str2.Format("%hu", id);
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			str1 = "序号：";
			str2.Format("%hu", seq);
			str1 += str2;
			pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			break;

	default: str2.Format("%d", icmph->type);
			 str1 += str2;
			 pTree->InsertItem(str1, 0, 0, hICMPItem, 0);

			 str1 = "代码：";
			 str2.Format("%d", icmph->code);

			 str1 = "校验和：";
			 str2.Format("0x%04hx", icmph->chksum);
			 str1 += str2;
			 pTree->InsertItem(str1, 0, 0, hICMPItem, 0);
			 break;
	}
}


/* 解析UDP */
void decodeUDP(udp_header *udph, HTREEITEM *hParent)
{
		HTREEITEM hUDPItem;		//树形控件结点
		CString str1, str2;

		str1 = "UDP （";
		str2.Format("%hu", ntohs(udph->srcport));
		str1 += str2 + " -> ";
		str2.Format("%hu", ntohs(udph->dstport));
		str1 += str2 + "）";
		hUDPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

		str1 = "源端口：";
		str2.Format("%hu", ntohs(udph->srcport));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hUDPItem, 0);

		str1 = "目的端口：";
		str2.Format("%hu", ntohs(udph->dstport));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hUDPItem, 0);

		str1 = "长度：";
		str2.Format("%hu", ntohs(udph->len));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hUDPItem, 0);

		str1 = "校验和：";
		str2.Format("0x%04hx", ntohs(udph->checksum));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hUDPItem, 0);

}

/* 解析TCP */
void decodeTCP(tcp_header *tcph, HTREEITEM *hParent)
{
		HTREEITEM hTCPItem;		//树形控件结点
		CString str1, str2;

		str1 = "TCP （";
		str2.Format("%d", ntohs(tcph->srcport));
		str1 += str2 + " -> ";
		str2.Format("%d", ntohs(tcph->dstport));
		str1 += str2 + "）";
		hTCPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

		str1 = "源端口：";
		str2.Format("%hu", ntohs(tcph->srcport));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hTCPItem, 0);

		str1 = "目的端口：";
		str2.Format("%hu", ntohs(tcph->dstport));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hTCPItem, 0);

		str1 = "序列号：";
		str2.Format("%lu", ntohl(tcph->seq));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hTCPItem, 0);

		str1 = "确认号：";
		str2.Format("%lu", ntohl(tcph->ack));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,  hTCPItem, 0);

		str1 = "首部长度：";
		str2.Format("%d (bytes)", (ntohs(tcph->hdrlen_rsv_flags) >> 12 ) * 4);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,  hTCPItem, 0);

		str1 = "标志：";
		str2.Format("0x%03x", ntohs(tcph->hdrlen_rsv_flags) & 0x0fff);
		str1 += str2;
		HTREEITEM hTCPFlag = pTree->InsertItem(str1, 0, 0,  hTCPItem, 0);

		str1 = "URG：";
		str2.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 5) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,hTCPFlag, 0);

		str1 = "ACK：";
		str2.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 4) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,hTCPFlag, 0);

		str1 = "PSH：";
		str2.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 3) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,hTCPFlag, 0);

		str1 = "RST：";
		str2.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 2) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,hTCPFlag, 0);

		str1 = "SYN：";
		str2.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 1) & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,hTCPFlag, 0);

		str1 = "FIN：";
		str2.Format("%d", ntohs(tcph->hdrlen_rsv_flags)  & 0x0001);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,hTCPFlag, 0);

		str1 = "窗口大小：";
		str2.Format("%hu", ntohs(tcph->win_size));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,  hTCPItem, 0);

		str1 = "校验和：";
		str2.Format("0x%04hx", ntohs(tcph->chksum));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,  hTCPItem, 0);

		str1 = "紧急指针：";
		str2.Format("%hu", ntohs(tcph->urg_ptr));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0,  hTCPItem, 0);


}


/* 解析DNS  offset为到dns首部的偏移量 */
void decodeDNS(u_char *pkt_data, int offset, dns_header *dnsh, HTREEITEM *hParent)
{
		HTREEITEM hDNSItem;			//树形控件结点
		CString str1, str2;

		str1 = "DNS （";
		switch(dnsh->flags >> 15)
		{
		case 0:	str2 = "Query）";		break;
		case 1:	str2 = "Response）";	break;
		}
		str1 += str2;
		hDNSItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

		str1 = "标识：";
		str2.Format("0x%04hx (%hu)", ntohs(dnsh->identifier), ntohs(dnsh->identifier)); 
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		str1 = "标志：";
		str2.Format("0x%04hx", ntohs(dnsh->flags));
		str1 += str2;

		HTREEITEM hDNSFlag = pTree->InsertItem(str1, 0, 0, hDNSItem, 0);
		/* 标志子字段 */
		str1 = "QR：";
		switch(ntohs(dnsh->flags) >> 15)
		{
		case 0: str2 = "0 （查询报文）"	;	break;
		case 1: str2 = "1 （响应报文）";	break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "OpCode：";
		switch((ntohs(dnsh->flags) >> 11) & 0x000f)
		{
		case 0: str2 = "0 （标准查询）";	break;
		case 1:	str2 = "1 （反向查询）";	break;
		case 2: str2 = "2 （服务器状态请求）"; break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "AA：";
		switch((ntohs(dnsh->flags) >> 10) & 0x0001)
		{
		case 0:	str2 = "0 （非授权回答）"; break;
		case 1: str1 = "1 （授权回答）"; break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "TC：";
		switch((ntohs(dnsh->flags) >> 9) & 0x0001)
		{
		case 0: str2 = "0 （报文未截断）"; break;
		case 1: str2 = "1 （报文截断）";	break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "RD：";
		switch((ntohs(dnsh->flags) >> 8) & 0x0001)
		{
		case 0: str2 = "0"; break;
		case 1: str2 = "1 （希望进行递归查询）";	break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "RA：";
		switch((ntohs(dnsh->flags) >> 7) & 0x0001)
		{
		case 0: str2 = "0 （服务器不支持递归查询）"; break;
		case 1: str2 = "1 （服务器支持递归查询）";	break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "Reserved：";
		str2.Format("%d", (ntohs(dnsh->flags) >> 4) & 0x0007);
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "rCode：";
		switch(ntohs(dnsh->flags)  & 0x000f)
		{
		case 0: str2 = "0 （无差错）";		break;
		case 1: str2 = "1 （格式差错）";	break;	
		case 2: str2 = "2 （DNS服务器问题）";	break;
		case 3: str2 = "3 （域名不存在或出错）";	break;
		case 4: str2 = "4 （查询类型不支持）";	break;
		case 5: str2 = "5 （在管理上禁止）";	break;
		default: str2.Format("%d（保留）", ntohs(dnsh->flags) & 0x000f);				break;
		}
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSFlag, 0);

		str1 = "查询记录数：";
		str2.Format("%hu", ntohs(dnsh->questions));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		str1 = "回答记录数：";
		str2.Format("%hu", ntohs(dnsh->answers));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		str1 = "授权回答记录数：";
		str2.Format("%hu", ntohs(dnsh->authority));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		str1 = "附加信息记录数：";
		str2.Format("%hu", ntohs(dnsh->additional));
		str1 += str2;
		pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		str1 = "查询部分：";
		HTREEITEM hDNSQuery = pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		/* 查询部分 */
		char *p = (char*)(pkt_data + offset + 12);	

		int query_num = 0, answer_num = 0, authority_num = 0, additional_num = 0;

		if(ntohs(dnsh->questions) < 10)
		{
			while(query_num < ntohs(dnsh->questions))
			{
				char *name1 = (char*)malloc(strlen(p)+1);

				translateName(name1, p);
			
				/* 跳过域名字段 */
				while(*p)
				{
					++p;
				}
				++p;

				str1.Format("%s", name1);
				str1 += "：";

				dns_query *dnsq = (dns_query*)p;
				u_short	type, classes;

				type = ntohs(dnsq->type);
				classes = ntohs(dnsq->classes);
				
				switch(type)
				{
				case 1:	str2 = "type A"; break;
				case 2:	str2 = "type NS"; break;
				case 5: str2 = "type CNAME"; break;
				case 6: str2 = "type SOA"; break;
				case 12: str2 = "type PTR"; break;
				case 15: str2 = "type MX"; break;
				case 28: str2 = "type AAAA"; break;
				case 255: str2 = "type ANY"; break;
				default: str2.Format("type UNKNOWN(%hu)", type); break;
				}
				str1 += str2 + ", ";

				switch(classes)
				{
				case 1: str2 = "class INTERNET"; break;
				case 2: str2 = "class CSNET";	break;
				case 3: str2 = "class COAS";	break;
				default: str2.Format("class UNKNOWN(%hu)", classes); break;
				}
				str1 += str2;

				pTree->InsertItem(str1, 0, 0, hDNSQuery, 0);

				/* 跳过查询类型和查询类字段 */
				p += sizeof(dns_query);

				query_num++;
				free(name1);
			}
		}

		str1 = "回答部分：";
		HTREEITEM hDNSAnswer = pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		/* 回答部分 */
		while(answer_num < ntohs(dnsh->answers))
		{

			/* 指向指针 */
			if(*(u_char*)p == 0xc0)
			{
				
				/* 指向偏移量 		
				++p;	
				
				char *name = (char*)(pkt_data + offset + *(u_char*)p);			// 域名
				char *name1 = (char*)malloc(strlen(name)+1);

			
				translateName(name1, name);
				
				str1.Format("%s", name1);
				str1 += "：";

  				free(name1);
				*/
					
				char name[70];
				char name1[70];

				translateData(pkt_data, offset, name, p, 2);
				translateName(name1, name);

				str1.Format("%s", name1);
				str1 += "：";

				/* 指向偏移量 */
				++p;


				/* 指向类型*/
				++p;
				dns_answer *dnsa = (dns_answer*)p;

				u_short type =  ntohs(dnsa->type);
				u_short classes = ntohs(dnsa->classes);
				u_long  ttl  = ntohl(dnsa->ttl);

				switch(type)
				{
				case 1:	str2 = "type A"; break;
				case 2:	str2 = "type NS"; break;
				case 5: str2 = "type CNAME"; break;
				case 6: str2 = "type SOA"; break;
				case 12: str2 = "type PTR"; break;
				case 15: str2 = "type MX"; break;
				case 28: str2 = "type AAAA"; break;
				case 255: str2 = "type ANY"; break;
				default: str2.Format("type UNKNOWN(%hu)", type); break;
				}
				str1 += str2 + ", ";

				switch(classes)
				{
				case 1: str2 = "class INTERNET"; break;
				case 2: str2 = "class CSNET";	break;
				case 3: str2 = "class COAS";	break;
				default: str2.Format("class UNKNOWN(%hu)", classes); break;
				}
				str1 += str2 + ", ";

				str2.Format("ttl %lu", ttl);
				str1 += str2 + ", ";

				/* 指向资源数据长度 */
				p += sizeof(dns_answer);
				
				u_short data_len = ntohs(*(u_short*)p);

				str2.Format("len %hu", data_len);
				str1 += str2 + ", ";

				/* 指向资源数据 */
				p += sizeof(u_short);

				/* 查询类型为NS、CNAME、PTR的资源数据 */
				if(type == 2 || type == 5 || type == 12)
				{
	
					/* 资源数据为指针0xc0 + 偏移量*/
					if(*(u_char*)p == 0xc0)
					{				
						/* 根据偏移量获取数据 											
						char *data = (char*)(pkt_data + offset + *(u_char*)(p+1));			// 域名
						char *data1 = (char*)malloc(strlen(data)+1);

						translateName(data1, data);

						str2.Format("%s", data1);
						str1 += str2;

						free(data1);
						*/
						char data[70];
						char data1[70];

						translateData(pkt_data, offset, data, p, 2);
						translateName(data1, data);

						str2.Format("%s", data1);
						str1 += str2;

					}
					/* 资源数据存在指针0xc0 + 偏移量 */
					else if(isNamePtr(p))
					{
						char data[70];
						char data1[70];

						translateData(pkt_data, offset, data, p, data_len);		// 去掉指针0xc0+偏移量
						translateName(data1, data);								// 去掉'.'

						str2.Format("%s", data1);
						str1 += str2;
					}
					/* 资源数据中不存在指针0xc0 + 偏移量 */
					else
					{
						char *data = (char*)malloc(data_len);

						translateName(data, p);

						str2.Format("%s", data);
						str1 += str2;
						free(data);
						
					}
				}
				/* 查询类型为A的资源数据 */
				else if(type == 1)
				{
					ip_address data = *(ip_address*)p;

					str2.Format("%d.%d.%d.%d", data.byte1, data.byte2, data.byte3, data.byte4);
					str1 += str2;
				}

				pTree->InsertItem(str1, 0, 0, hDNSAnswer, 0);
			
				/* 跳过数据部分 */
				p += data_len;

		

			}//if
			answer_num++;
		}

		str1 = "授权回答部分：";
		HTREEITEM hDNSAuthority = pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		/* 授权回答部分 */
		while(authority_num < ntohs(dnsh->authority))
		{

			/* 指向指针 */
			if(*(u_char*)p == 0xc0)
			{
				
				/* 指向偏移量 		
				++p;	
				
				char *name = (char*)(pkt_data + offset + *(u_char*)p);			// 域名
				char *name1 = (char*)malloc(strlen(name)+1);
				translateName(name1, name);
				
				str1.Format("%s", name1);
				str1 += "：";

				free(name1);
				*/
				char name[70];
				char name1[70];

				translateData(pkt_data, offset, name, p, 2);
				translateName(name1, name);

				str1.Format("%s", name1);
				str1 += "：";

				/* 指向偏移量 */
				++p;

				/* 指向类型*/
				++p;
				dns_answer *dnsa = (dns_answer*)p;

				u_short type =  ntohs(dnsa->type);
				u_short classes = ntohs(dnsa->classes);
				u_long  ttl  = ntohl(dnsa->ttl);

				switch(type)
				{
				case 1:	str2 = "type A"; break;
				case 2:	str2 = "type NS"; break;
				case 5: str2 = "type CNAME"; break;
				case 6: str2 = "type SOA"; break;
				case 12: str2 = "type PTR"; break;
				case 15: str2 = "type MX"; break;
				case 28: str2 = "type AAAA"; break;
				case 255: str2 = "type ANY"; break;
				default: str2.Format("type UNKNOWN(%hu)", type); break;
				}
				str1 += str2 + ", ";

				switch(classes)
				{
				case 1: str2 = "class INTERNET"; break;
				case 2: str2 = "class CSNET";	break;
				case 3: str2 = "class COAS";	break;
				default: str2.Format("class UNKNOWN(%hu)", classes); break;
				}
				str1 += str2 + ", ";

				str2.Format("ttl %lu", ttl);
				str1 += str2 + ", ";

				/* 指向资源数据长度 */
				p += sizeof(dns_answer);
				
				u_short data_len = ntohs(*(u_short*)p);

				str2.Format("len %hu", data_len);
				str1 += str2 + ", ";

				/* 指向资源数据 */
				p += sizeof(u_short);

				/* 查询类型为NS、CNAME、PTR的资源数据 */
				if(type == 2 || type == 5 || type == 12)
				{
	
					/* 资源数据为指针0xc0 + 偏移量*/
					if(*(u_char*)p == 0xc0)
					{				
						/* 根据偏移量获取数据 											
						char *data = (char*)(pkt_data + offset + *(u_char*)(p+1));			// 域名
						char *data1 = (char*)malloc(strlen(data)+1);

						translateName(data1, data);

						str2.Format("%s", data1);
						str1 += str2;

						free(data1);
						*/

						char data[70];
						char data1[70];

						translateData(pkt_data, offset, data, p, 2);
						translateName(data1, data);

						str2.Format("%s", data1);
						str1 += str2;
					}
					/* 资源数据存在指针0xc0 + 偏移量 */
					else if(isNamePtr(p))
					{
						char data[70];
						char data1[70];

						translateData(pkt_data, offset, data, p, data_len);		// 去掉指针0xc0+偏移量
						translateName(data1, data);								// 去掉'.'

						str2.Format("%s", data1);
						str1 += str2;
					}
					/* 资源数据中不存在指针0xc0 + 偏移量 */
					else
					{
						char *data = (char*)malloc(data_len);

						translateName(data, p);

						str2.Format("%s", data);
						str1 += str2;
						free(data);
						
					}
				}
				/* 查询类型为A的资源数据 */
				else if(type == 1)
				{
					ip_address data = *(ip_address*)p;

					str2.Format("%d.%d.%d.%d", data.byte1, data.byte2, data.byte3, data.byte4);
					str1 += str2;
				}

				pTree->InsertItem(str1, 0, 0, hDNSAuthority, 0);
			
				/* 跳过数据部分 */
				p += data_len;


			}//if
			authority_num++;
		}

		str1 = "附加信息部分：";
		HTREEITEM hDNSAdditional = pTree->InsertItem(str1, 0, 0, hDNSItem, 0);

		/* 附加信息部分 */
		while(additional_num < ntohs(dnsh->additional))
		{

			/* 指向指针 */
			if(*(u_char*)p == 0xc0)
			{
				
				/* 指向偏移量 		
				++p;	
				
				char *name = (char*)(pkt_data + offset + *(u_char*)p);			// 域名
				char *name1 = (char*)malloc(strlen(name)+1);

				translateName(name1, name);
				
				str1.Format("%s", name1);
				str1 += "：";

				free(name1);
				*/
				char name[70];
				char name1[70];

				translateData(pkt_data, offset, name, p, 2);
				translateName(name1, name);

				str1.Format("%s", name1);
				str1 += "：";

				/* 指向偏移量 */
				++p;

				/* 指向类型*/
				++p;
				dns_answer *dnsa = (dns_answer*)p;

				u_short type =  ntohs(dnsa->type);
				u_short classes = ntohs(dnsa->classes);
				u_long  ttl  = ntohl(dnsa->ttl);

				switch(type)
				{
				case 1:	str2 = "type A"; break;
				case 2:	str2 = "type NS"; break;
				case 5: str2 = "type CNAME"; break;
				case 6: str2 = "type SOA"; break;
				case 12: str2 = "type PTR"; break;
				case 15: str2 = "type MX"; break;
				case 28: str2 = "type AAAA"; break;
				case 255: str2 = "type ANY"; break;
				default: str2.Format("type UNKNOWN(%hu)", type); break;
				}
				str1 += str2 + ", ";

				switch(classes)
				{
				case 1: str2 = "class INTERNET"; break;
				case 2: str2 = "class CSNET";	break;
				case 3: str2 = "class COAS";	break;
				default: str2.Format("class UNKNOWN(%hu)", classes); break;
				}
				str1 += str2 + ", ";

				str2.Format("ttl %lu", ttl);
				str1 += str2 + ", ";

				/* 指向资源数据长度 */
				p += sizeof(dns_answer);
				
				u_short data_len = ntohs(*(u_short*)p);

				str2.Format("len %hu", data_len);
				str1 += str2 + ", ";

				/* 指向资源数据 */
				p += sizeof(u_short);

				/* 查询类型为NS、CNAME、PTR的资源数据 */
				if(type == 2 || type == 5 || type == 12)
				{
	
					/* 资源数据为指针0xc0 + 偏移量*/
					if(*(u_char*)p == 0xc0)
					{				
						/* 根据偏移量获取数据 											
						char *data = (char*)(pkt_data + offset + *(u_char*)(p+1));			// 域名
						char *data1 = (char*)malloc(strlen(data)+1);

						translateName(data1, data);

						str2.Format("%s", data1);
						str1 += str2;

						free(data1);
						*/

						char data[70];
						char data1[70];

						translateData(pkt_data, offset, data, p, 2);
						translateName(data1, data);

						str2.Format("%s", data1);
						str1 += str2;
					}
					/* 资源数据存在指针0xc0 + 偏移量 */
					else if(isNamePtr(p))
					{
						char data[70];
						char data1[70];

						translateData(pkt_data, offset, data, p, data_len);		// 去掉指针0xc0+偏移量
						translateName(data1, data);								// 去掉'.'

						str2.Format("%s", data1);
						str1 += str2;
					}
					/* 资源数据中不存在指针0xc0 + 偏移量 */
					else
					{
						char *data = (char*)malloc(data_len);

						translateName(data, p);

						str2.Format("%s", data);
						str1 += str2;
						free(data);
						
					}
				}
				/* 查询类型为A的资源数据 */
				else if(type == 1)
				{
					ip_address data = *(ip_address*)p;

					str2.Format("%d.%d.%d.%d", data.byte1, data.byte2, data.byte3, data.byte4);
					str1 += str2;
				}

				pTree->InsertItem(str1, 0, 0, hDNSAdditional, 0);
			
				/* 跳过数据部分 */
				p += data_len;

			}//if
			additional_num++;
		}		
}

/* 解析HTTP offset为到HTTP报文的偏移量*/
void decodeHTTP(u_char *pkt_data, int offset, HTREEITEM *hParent)
{
	u_char *p = (pkt_data + offset);
	ip_header *iph = (ip_header*)(pkt_data + 14);
	tcp_header *tcph = (tcp_header*)(pkt_data + 14 + (iph->ver_hrdlen & 0x0f) *4);

	int http_len = ntohs(iph->totallen) - (iph->ver_hrdlen & 0x0f) * 4 - (ntohs(tcph->hdrlen_rsv_flags) >> 12)*4;
	int count = 0;

	CString str1;
	
	str1 = "HTTP";
	HTREEITEM hHTTPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

	
	while( count < http_len)
	{
		str1 = "";
		while(*p != '\r')
		{
			str1 += *p;
			++p;
			++count;
		}
		str1 += "\\r\\n";
		pTree->InsertItem(str1, 0, 0, hHTTPItem, 0);

		p += 2;
		count += 2;
	}	
}


/* 解析DHCP offset为到DHCP报文的偏移量*/
void decodeDHCP(u_char *pkt_data, int offset, HTREEITEM *hParent)
{
	dhcp_header *dhcph = (dhcp_header*)(pkt_data + offset);
	u_char *p = (u_char*)(pkt_data + offset + sizeof(dhcp_header));	//p指向客户机硬件地址

	CString str1, str2;

	str1 = "DHCP";
	HTREEITEM hDHCPItem = pTree->InsertItem(str1, 0, 0, *hParent, 0);

	/* 解析dhcp首部 */
	str1 = "报文类型：";
	str2.Format("%d", dhcph->op);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

	str1 = "硬件类型：";
	str2.Format("%d", dhcph->htype);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

	str1 = "硬件地址长度：";
	str2.Format("%d", dhcph->hlen);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

	str1 = "跳数：";
	str2.Format("%d", dhcph->hops);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

	str1 = "事务ID：";
	str2.Format("0x%08lx", ntohl(dhcph->xid));
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	str1 = "客户启动时间：";
	str2.Format("%hu", ntohs(dhcph->secs));
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	str1 = "标志：";
	str2.Format("0x%04hx", ntohs(dhcph->flags));
	str1 += str2;
	switch(ntohs(dhcph->flags) >> 15)
	{
	case 0: str1 += "（广播）"; break;
	case 1: str1 += "（单播）"; break;
	}
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	str1 = "客户机IP地址：";
	str2.Format("%d.%d.%d.%d", dhcph->ciaddr.byte1, dhcph->ciaddr.byte2, dhcph->ciaddr.byte3, dhcph->ciaddr.byte4);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	str1 = "你的（客户）IP地址：";
	str2.Format("%d.%d.%d.%d", dhcph->yiaddr.byte1, dhcph->yiaddr.byte2, dhcph->yiaddr.byte3, dhcph->yiaddr.byte4);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	str1 = "服务器IP地址：";
	str2.Format("%d.%d.%d.%d", dhcph->siaddr.byte1, dhcph->siaddr.byte2, dhcph->siaddr.byte3, dhcph->siaddr.byte4);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	str1 = "网关IP地址：";
	str2.Format("%d.%d.%d.%d", dhcph->giaddr.byte1, dhcph->giaddr.byte2, dhcph->giaddr.byte3, dhcph->giaddr.byte4);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	/*  解析dhcp首部剩余部分 */
	mac_address *chaddr = (mac_address*)p; 
						
	str1 = "客户机mac地址：";
	str2.Format("%02x-%02x-%02x-%02x-%02x-%02x", chaddr->byte1, chaddr->byte2, chaddr->byte3, chaddr->byte4, chaddr->byte5, chaddr->byte6);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	// 跳过客户机硬件地址
	p += 16;		

	str1 = "服务器主机名：";
	str2.Format("%s", p);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0,hDHCPItem, 0);

	// 跳过服务器主机名
	p += 64;		

	str1 = "引导文件名：";
	str2.Format("%s", p);
	str1 += str2;
	pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

	// 跳过引导文件名
	p += 128;

	if(ntohl(*(u_long*)p) == 0x63825363)
	{
		str1 = "Magic cookie: DHCP";
		pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);
	}

	// 跳过magic cookie
	p += 4;

	while(*p != 0xff)
	{
		switch(*p)
		{
		case 53: 
			{	str1 = "选项：（53）DHCP报文类型";
				 switch(*(p+2))
				 {
					case 1: str1 += "（Discover）"; break;
					case 2: str1 += "（Offer）"; break;
					case 3: str1 += "（Request）"; break;
					case 4: str1 += "（Decline）"; break;
					case 5: str1 += "（ACK）"; break;
					case 6: str1 += "（NAK）"; break;
					case 7: str1 += "（Release）"; break;
					case 8: str1 += "（Inform）"; break;
				 }
				 HTREEITEM hDHCPOption;
				 hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 str1 = "长度：";
				 str2.Format("%d", *(++p));
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 str1 = "DHCP：";
				 str2.Format("%d", *(++p));
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);
				 
				 // 指向下一个选项
				 ++p;
			}
			break;

		case 50: 
			{	
				str1 = "选项：（50）请求IP地址";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 str1 = "长度：";
				 str2.Format("%d", *(++p));
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 ip_address *addr = (ip_address*)(++p);
				 str1 = "地址：";
				 str2.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	
				 
				 // 指向下一个选项
				 p += 4;
			}
				 break;

		case 51:
			{
				str1 = "选项：（51）IP地址租约时间";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);	

				 str1 = "长度：";
				 str2.Format("%d", *(++p));
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 u_int time = *(++p);
				 str1 = "租约时间：";
				 str2.Format("%u", time);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 // 指向下一个选项
				 p += 4;
			}
				 break;

		case 61: 
			{
				 str1 = "选项：（61）客户机标识";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 str1 = "硬件类型：";
				 if(*(++p) == 0x01)
				 {
					str2 = "以太网（0x01）";		
					str1 += str2;
					pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

					mac_address *addr = (mac_address*)(++p);
					str1 = "客户机标识：";
					str2.Format("%02x-%02x-%02x-%02x-%02x-%02x", addr->byte1, addr->byte2, addr->byte3, addr->byte4, addr->byte5, addr->byte6);
					str1 += str2;
					pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

					p += 6;
				 }
				 else
				 {
					str2.Format("%d", *p);
					str1 += str2;
					pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

					p += len;

				 }	
			}
				 break;

		case 60: 
			{
				 str1 = "选项：（60）供应商类标识";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 int count = 0;
				 str1 = "供应商类标识：";

				 for(;count < len; count++)
				 {
					 str2.Format("%c", *(++p));
					 str1 += str2;
				 }
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	 

				 ++p;
			}
				 break;

		case 54: 
			{	
				 str1 = "选项：（54）服务器标识";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 ip_address *addr = (ip_address*)(++p);
				 str1 = "服务器标识：";
				 str2.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 p += 4;
			}
				 break;

		case 1:	 
			{
				 str1 = "选项：（1）子网掩码";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 ip_address *submask = (ip_address*)(++p);
				 str1 = "子网掩码：";
				 str2.Format("%d.%d.%d.%d", submask->byte1, submask->byte2, submask->byte3, submask->byte4);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 p += 4;
			}
				 break;

		case 3:  
			{
				 str1 = "选项：（3）路由器";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

				 int count = 0;
				 while( count < len)
				 {
					 ip_address *addr = (ip_address*)(++p);
					 str1 = "路由器：";
					 str2.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
					 str1 += str2;
					 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

					 count += 4;
					 p += 4;
				 }
			}
				 break;

		case 6:  
			{
				 str1 = "选项：（6）DNS服务器";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	 

				 int count = 0;
				 ++p;
				 while( count < len)
				 {
					 ip_address *addr = (ip_address*)p;
					 str1 = "DNS服务器：";
					 str2.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
					 str1 += str2;
					 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	

					 count += 4;
					 p += 4;
				 }
			}
				 break;


		case 12: 
			{	
				 str1 = "选项：（12）主机名";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	 

				 int count = 0;
				 str1 = "主机名：";

				 for(;count < len; count++)
				 {
					 str2.Format("%c", *(++p));
					 str1 += str2;
				 }
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	 

				 ++p;
			}
				 break;

		case 0: ++p;
				break;

		default: str1 = "选项：（";
				 str2.Format("%d", *p);
				 str1 += str2 + "）";
				 HTREEITEM hDHCPOption = pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);

				 int len = *(++p);
				 str1 = "长度：";
				 str2.Format("%d", len);
				 str1 += str2;
				 pTree->InsertItem(str1, 0, 0, hDHCPOption, 0);	 

				 // 指向选项内容
				 ++p;

				 // 跳过选项内容
				 p += len;
				 break;
		}

	}
	str1 = "选项：（255）结束";
	pTree->InsertItem(str1, 0, 0, hDHCPItem, 0);	 
	


}

/* 判断data中有无指针0xc0,并返回指针在data中的位置*/
int isNamePtr(char *data)
{
	char *p = data;
	int pos = 0;

	while(*p)
	{
		if(*(u_char*)p == 0xc0)
		{
			return pos;
		}
		++p;
		++pos;
	}

	return 0;
}
void translateName(char *name1, const char *name2)
{
	strcpy(name1, name2);

	char *p = name1;
	bool canMove = false;

	if( !isalnum(*(u_char*)p) && *(u_char*)p !=  '-')
	{
		canMove = true;
	}

	/* 将计数转换为'.' */
	while(*p)
	{
		if(!isalnum(*(u_char*)p) && *(u_char*)p != '-')
			*p = '.';

		++p;
	}


	/* 将域名整体向前移1位 */
	if(canMove)
	{
		p = name1;
		while(*p)
		{
			*p = *(p+1);
			++p;
		}
	}

	
}

/* DNS资源记录数据部分转换 将带有指针0xc0的data2转换为不带指针的data1 offset为到dns首部的偏移量*/
void translateData(u_char *pkt_data, int offset, char *data1, char *data2, int data2_len)
{
	char *p = data2;
	int count = 0, i = 0;

	/* 遍历data2 */
	while(count < data2_len )
	{			
		/* 指针 */
		if(*(u_char*)p == 0xc0)
		{
			++p;

			/* 读取指针所指向的数据 */
			char *data_ptr = (char*)(pkt_data + offset + *(u_char*)p);

			int pos;
			pos = isNamePtr(data_ptr);
			if(pos)
			{
				translateData(pkt_data, offset, data1+i, data_ptr, pos+2);
			}
			else
			{
				strcpy(data1+i, data_ptr);
				i += strlen(data_ptr)+1;
			}
			count += 2;
		}
		else 
		{
			data1[i++] = *p;
			++p;
			++count;
		}

	}
}




/* 点击列表事件 */
void CSnifferUIDlg::OnClickList1(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	
	HTREEITEM hIDItem;		//树形控件结点

	int sel_row;
	u_short *eth_type;
	mac_address *saddr, *daddr;
	arp_header	*arph;
	ip_header	*iph;
	icmp_header *icmph;
	udp_header	*udph;
	tcp_header	*tcph;
	dns_header	*dnsh;

	CString str1,str2;
	

	/* 删除所有结点 */
	m_tree.DeleteAllItems();

	/* 获取选中行的行号 */
	sel_row = pList1->GetSelectionMark();

	/* 获取选中行的报文信息 */
	POSITION pos = linklist.FindIndex(sel_row);
	packet_header *ppkth = &linklist.GetAt(pos);
	if(ppkth == NULL)
	{
		AfxMessageBox("ppkth为空指针", MB_OK);
		return;
	}

	saddr = &ppkth->saddr;
	daddr = &ppkth->daddr;
	eth_type = &ppkth->eth_type;
	arph = ppkth->arph;
	iph = ppkth->iph;
	icmph = ppkth->icmph;
	udph = ppkth->udph;
	tcph = ppkth->tcph;
	dnsh = ppkth->dnsh;

	/* 打印数据包到编辑框 */
	int count = 0;
	u_char *p = ppkth->pkt_data;
	while(count < ppkth->caplen)
	{
		str2.Format("%02hx ", *p);
		str1 += str2;

		++p;
		++count;
	}	
	GetDlgItem(IDC_EDIT1)->SetWindowText(str1);


	/* 建立编号结点 */
	str1.Format("第%d个数据包", sel_row + 1);
	hIDItem = m_tree.InsertItem(str1);

	/* 建立以太网帧结点 */
	decodeFrame(saddr, daddr, eth_type, &hIDItem);
	
	/* 建立ip结点 */
	if(iph != NULL)
	{
		decodeIP(iph, &hIDItem);		
	}
	
	/* 建立arp结点 */
	if(arph != NULL)
	{
		decodeARP(arph, &hIDItem);
	}

	/* 建立icmp结点 */
	if(icmph != NULL)
	{
		decodeICMP(icmph, &hIDItem);
	}
															
	/* 建立udp结点 */
	if(udph != NULL)
	{
		decodeUDP(udph, &hIDItem);	
	}

	/* 建立tcp结点 */
	if(tcph != NULL)
	{
		decodeTCP(tcph, &hIDItem);
	}

	/* 建立dns结点 */
	if(dnsh != NULL)
	{
		int offset;

		switch(iph->proto)
		{
		case 6:	 offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + (ntohs(tcph->hdrlen_rsv_flags) >> 12)*4;	break;	//tcph
		case 17: offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + 8 ;	break;											//udph 
			
		}
		 
															
		decodeDNS(ppkth->pkt_data, offset, dnsh, &hIDItem);	
	}

	/* 建立http结点 */
	if(tcph != NULL && (ntohs(tcph->srcport) == 80 || ntohs(tcph->dstport) == 80))
	{
		int offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + (ntohs(tcph->hdrlen_rsv_flags) >> 12)*4;

		decodeHTTP(ppkth->pkt_data, offset,&hIDItem);
	}

	/* 建立dhcp结点 */
	if(udph != NULL && ( (ntohs(udph->srcport) == 67 && ntohs(udph->dstport) == 68) || (ntohs(udph->srcport) == 68 && ntohs(udph->dstport) == 67) ))
	{
		int offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + 8;

		decodeDHCP(ppkth->pkt_data, offset, &hIDItem);
	}
	*pResult = 0;
}

