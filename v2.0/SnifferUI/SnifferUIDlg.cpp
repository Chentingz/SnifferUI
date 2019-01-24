// SnifferUIDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SnifferUI.h"
#include "SnifferUIDlg.h"

//#include "packet_header.h"
#include "Global.h"
//#include "string.h"
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
public:
	afx_msg void OnNMClickSyslink1(NMHDR *pNMHDR, LRESULT *pResult);
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
	ON_NOTIFY(NM_CLICK, IDC_SYSLINK1, &CAboutDlg::OnNMClickSyslink1)
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
	DDX_Control(pDX, IDC_START, btnStart_);
	DDX_Control(pDX, IDC_PAUSE, btnPause_);
	DDX_Control(pDX, IDC_STOP, btnStop_);
	DDX_Control(pDX, IDC_COMBO1, comboboxDevlist_);
	DDX_Control(pDX, IDC_LIST1, listctrlPacketList_);
	DDX_Control(pDX, IDC_TREE1, treectrlPacketInfo_);
	DDX_Control(pDX, IDC_EDIT1, editCtrlPacketData_);
	
	//}}AFX_DATA_MAP

	
}

BEGIN_MESSAGE_MAP(CSnifferUIDlg, CDialog)
	//{{AFX_MSG_MAP(CSnifferUIDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, OnClickedStart)
	ON_BN_CLICKED(IDC_PAUSE, OnClickedPause)
	ON_BN_CLICKED(IDC_STOP, OnClickedStop)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, OnClickList1)
	//}}AFX_MSG_MAP
//	ON_BN_CLICKED(IDC_PAUSE, &CSnifferUIDlg::OnBnClickedPause)
ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSnifferUIDlg::OnCustomdrawList1)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIDlg message handlers

/**
*	@brief UI界面初始化
*	@param
*	@return
*/
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

	/* 控件指针初始化 */
	g_pBtnStart = &btnStart_;
	g_pBtnPause = &btnPause_;
	g_pBtnStop = &btnStop_;
	g_pComboBoxDevList = &comboboxDevlist_;
	g_pListCtrlPacketList = &listctrlPacketList_;
	g_pTreeCtrlPacketInfo = &treectrlPacketInfo_;
	g_pEditCtrlPacketData = &editCtrlPacketData_;

	///* 按钮初始化 */
	//g_pBtnStart->SetIcon(LoadIcon(AfxGetApp()->m_hInstance, MAKEINTRESOURCE(IDI_ICON1)));
	//g_pBtnPause->SetIcon(LoadIcon(AfxGetApp()->m_hInstance, MAKEINTRESOURCE(IDI_ICON2)));
	//g_pBtnStop->SetIcon(LoadIcon(AfxGetApp()->m_hInstance, MAKEINTRESOURCE(IDI_ICON3)));


	/* 列表控件初始化 */
	initialListCtrlPacketList();

	/* 下拉列表初始化，显示网卡列表*/
	initialComboBoxDevList();

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

/**
*	@brief	按下开始按钮，开始抓包
*	@param	-
*	@return	-
*/
void CSnifferUIDlg::OnClickedStart()
{
	/* 若没有选中网卡，报提示信息；否则，创建线程抓包 */
	if (g_pComboBoxDevList->GetCurSel() == CB_ERR)
	{
		AfxMessageBox(_T("请选择网卡"), MB_OK);
	}
	else
	{
		g_pBtnStart->EnableWindow(FALSE);
		g_pBtnPause->EnableWindow(TRUE);
		g_pBtnStop->EnableWindow(TRUE);
		g_pComboBoxDevList->EnableWindow(FALSE);
		myWinThread = AfxBeginThread(capture_thread, NULL, 0, NULL, 0, NULL);
	}
}

/**
*	@brief	按下暂停按钮，暂停抓包
*	@param	-
*	@return -
*/
void CSnifferUIDlg::OnClickedPause()
{
	if (g_pBtnStart->IsWindowEnabled() == false && g_pBtnPause->IsWindowEnabled() == true && g_pBtnStop->IsWindowEnabled() == true)
	{
		g_pBtnStart->EnableWindow(TRUE);
		g_pBtnPause->EnableWindow(FALSE);
		g_pBtnStop->EnableWindow(TRUE);
		g_pComboBoxDevList->EnableWindow(TRUE);
		pcap_breakloop(g_pAdhandle);
	}
}

/**
*	@brief	按下结束按钮，停止抓包，删除打印的数据包相关信息，清除数据包链表,并重新开始抓包
*	@param	-
*	@return -
*/
void CSnifferUIDlg::OnClickedStop() 
{
	g_pBtnStart->EnableWindow(TRUE);
	g_pBtnPause->EnableWindow(FALSE);
	g_pBtnStop->EnableWindow(FALSE);
	g_pComboBoxDevList->EnableWindow(TRUE);
	pcap_breakloop(g_pAdhandle);

	g_pListCtrlPacketList->DeleteAllItems();
	g_pTreeCtrlPacketInfo->DeleteAllItems();
	g_pEditCtrlPacketData->Clear();

	g_listctrlPacketListRows = -1;
	g_listctrlPacketListCols = 0;
	g_listctrlPacketListCount = 0;

	// TODO 打断点看是否清除链表
	if (!g_packetLinkList.IsEmpty())
	{
		g_packetLinkList.RemoveAll();
	}
}


/**
*	@brief 捕获数据包线程入口函数，全局函数 
*	@param pParam 传入线程的参数
*	@return 0 表示抓包成功	-1 表示抓包失败
*/	
UINT capture_thread(LPVOID pParam)
{
	/* 获取并打开选中的网卡 */
	int selIndex = g_pComboBoxDevList->GetCurSel();
	if(selIndex == CB_ERR )
	{
		AfxMessageBox(_T("请选择网卡"),MB_OK);
		return -1;
	}		
	int count = 0;
    for(g_pDev = g_pAllDevs; count < selIndex; g_pDev = g_pDev->next, ++count);
	if((g_pAdhandle = pcap_open_live(g_pDev->name,
					65535,
					 PCAP_OPENFLAG_PROMISCUOUS,
					1000,
					g_errbuf)) == NULL)
	{ 
		AfxMessageBox(_T("pcap_open_live错误!"), MB_OK);
	}

	/* 判断接口的链路层类型是否为以太网*/
	if( pcap_datalink(g_pAdhandle) != DLT_EN10MB)
		AfxMessageBox(_T("数据链路层不是以太网"), MB_OK);

	
	pcap_dumper_t *dumpfile = NULL;	
	/* 打开堆文件
	strcpy(filename, "pkt_cap");

	dumpfile = pcap_dump_open(adhandle, filename);
	*/

	/* 开始捕获数据包 */
	pcap_loop(g_pAdhandle, -1,	packet_handler, (unsigned char *)dumpfile);
	
	return 0;
}

/**
*	@brief	捕获数据包处理函数，全局回调函数
*	@param	dumpfile	用于存储数据包的堆文件	
*	@param	header		数据包首部
*	@param	pkt_data	数据包（帧）
*	@return	
*/
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* 写入堆文件 */
//	pcap_dump(dumpfile, header, pkt_data);
	

	/* 日志文件 
	char *path = "E:\\Code\\Sniffer\\pkt_cap_log.txt";
	FILE *save_file;
	save_file = fopen(path,"a");	//以追加形式写入
	*/
	
	/* 存储数据包到链表 */
	Packet pkt(pkt_data, header);

	g_packetLinkList.AddTail(pkt);
	Packet &pkt1 = g_packetLinkList.GetTail();
	printListCtrlPacketList(pkt1);
	
	//fclose(save_file);
}

/**
*	@brief	获取本地机器网卡列表,并打印网卡描述到下拉列表中
*	@param	-
*	@return -
*/
void initialComboBoxDevList()
{
	if (pcap_findalldevs(&g_pAllDevs, g_errbuf) == -1)
	{
		fprintf(stderr, "pcap_findalldevs()错误: %s\n", g_errbuf);
		exit(1);
	}
	for (g_pDev = g_pAllDevs; g_pDev != NULL; g_pDev = g_pDev->next)
	{
		if (g_pDev->description != NULL)
		{
			g_pComboBoxDevList->AddString(g_pDev->description);
		}			
	}
}

/**
*	@brief	列表控件初始化
*	@param	-
*	@return -
*/
void initialListCtrlPacketList()
{
	DWORD dwStyle = g_pListCtrlPacketList->GetExtendedStyle();	// 添加列表控件的网格线
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;

	g_pListCtrlPacketList->SetExtendedStyle(dwStyle);
	g_pListCtrlPacketList->InsertColumn(0, "编号", LVCFMT_CENTER, 40);
	g_pListCtrlPacketList->InsertColumn(1, "时间", LVCFMT_CENTER, 140);
	g_pListCtrlPacketList->InsertColumn(2, "协议", LVCFMT_CENTER, 60);
	g_pListCtrlPacketList->InsertColumn(3, "长度", LVCFMT_CENTER, 50);
	g_pListCtrlPacketList->InsertColumn(4, "源MAC地址", LVCFMT_CENTER, 180);
	g_pListCtrlPacketList->InsertColumn(5, "目的MAC地址", LVCFMT_CENTER, 180);
	g_pListCtrlPacketList->InsertColumn(6, "源IP地址", LVCFMT_CENTER, 120);
	g_pListCtrlPacketList->InsertColumn(7, "目的IP地址", LVCFMT_CENTER, 120);

}


/**
*	@brief	打印数据包概要信息到列表控件
*	@param	数据包
*	@return	0 打印成功	-1 打印失败
*/
int printListCtrlPacketList(const Packet &pkt)
{
	if (pkt.isEmpty())
	{
		return -1;
	}
	/* 打印编号 */
	CString	strCount;
	strCount.Format("%d", ++g_listctrlPacketListCount);
	g_pListCtrlPacketList->InsertItem(++g_listctrlPacketListRows, strCount);

	/* 打印时间 */
	CTime pktArrivalTime( (time_t)(pkt.header->ts.tv_sec) ) ;
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");
	g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, strPktArrivalTime);

	/* 打印协议 */	
	if (!pkt.protocol.IsEmpty())
	{
		g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, pkt.protocol);
		//COLORREF ref = RGB(120, 250, 110);
		///*if(pkt.protocol == "TCP")
		//	g_pListCtrlPacketList->SetTextBkColor(ref);*/
		//
	}
	else
	{
		++g_listctrlPacketListCols;
	}

	/* 打印长度 */
	CString strCaplen;
	strCaplen.Format("%d", pkt.header->caplen);
	g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, strCaplen);

	/* 打印源目MAC地址 */
	if (pkt.ethh != NULL)
	{
		CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
		CString strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);

		g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, strSrcMAC);
		g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, strDstMAC);
	}
	else
	{
		g_listctrlPacketListCols += 2;
	}

	/* 打印源目IP地址 */
	if (pkt.iph != NULL)
	{
		CString strSrcIP = IPAddr2CString(pkt.iph->srcaddr);
		CString strDstIP = IPAddr2CString(pkt.iph->dstaddr);

		g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, strSrcIP);
		g_pListCtrlPacketList->SetItemText(g_listctrlPacketListRows, ++g_listctrlPacketListCols, strDstIP);
	}
	else
	{
		g_listctrlPacketListCols += 2;
	}
	g_listctrlPacketListCols = 0;		// 列复位 

	return 0;
}

/**
*	@brief	打印数据包概要信息到列表控件
*	@param	数据包链表
*	@return	0 打印成功	-1 打印失败
*/
int printListCtrlPacketList(const CList<Packet, Packet> &packetLinkList)
{
	if (packetLinkList.IsEmpty())
	{
		return -1;
	}
	for (int i = 0; i < packetLinkList.GetCount(); ++i)
	{
		POSITION pos = packetLinkList.FindIndex(i);
		printListCtrlPacketList(g_packetLinkList.GetAt(pos));
	}
	return 0;
}

/**
*	@brief 打印数据包数据到编辑框
*	@param	pkt	数据包
*	@return 0 打印成功	-1 打印失败
*/
int printEditCtrlPacketData(const Packet & pkt)
{
	if (pkt.isEmpty())
	{
		return -1;
	}
	CString strPacketData, strTmp;
	u_char* pHexPacketData = pkt.pkt_data;
	u_char* pASCIIPacketData = pkt.pkt_data;
	for (int i = 0,  count16=1, offset = 0; i < pkt.header->caplen && pHexPacketData != NULL; ++i, ++count16)
	{
		// 打印行首偏移量
		if (i % 16 == 0)
		{
			strTmp.Format("%04X:", offset);
			strPacketData += strTmp + " ";
		}

		// 打印16进制数据
		strTmp.Format("%02X", *pHexPacketData);
		strPacketData += strTmp + " ";
		++pHexPacketData;

		// 每8个字节数据打印一个制表符
		if (count16 == 8)
		{
			strPacketData += "\t";
		}

		// 每16个字节数据打印ASCII字符数据，只打印字母数字
		if (count16 == 16)
		{
			strPacketData += " ";
			for (int j=0; j < 16; ++j, ++pASCIIPacketData)
			{
				strTmp.Format("%c", isalnum(*pASCIIPacketData) ? *pASCIIPacketData : '.');
				strPacketData += strTmp;
			}
			strPacketData += "\r\n";
			offset += 16;
			count16 = 0;
		}
	}
	// 打印剩余ASCII字节
	for (int j = 0, count16= (pkt.header->caplen % 16); j < 16 - (pkt.header->caplen % 16); ++j, ++count16)
	{
		strPacketData += "   ";
		if (count16 == 8)
		{
			strPacketData += "\t";
		}
	}
	strPacketData += " ";
	for (int j = 0; j < (pkt.header->caplen % 16); ++j, ++pASCIIPacketData)
	{
		strTmp.Format("%c", isalnum(*pASCIIPacketData) ? *pASCIIPacketData : '.');
		strPacketData += strTmp;
	}
	strPacketData += "\r\n";
	
	g_pEditCtrlPacketData->SetWindowTextA(strPacketData);

	return 0;
}

/**
*	@brief	打印数据包首部解析结果到树形控件
*	@param	pkt	数据包
*	@return	0 打印成功	-1 打印失败
*/
int printTreeCtrlPacketInfo(const Packet &pkt, int pktIndex)
{
	g_pTreeCtrlPacketInfo->DeleteAllItems();

	/* 建立编号结点 */
	CString strText;

	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");

	strText.Format("第%d个数据包（%s, 共 %hu 字节, 捕获 %hu 字节）", pktIndex + 1, strPktArrivalTime, pkt.header->len, pkt.header->caplen);

	HTREEITEM rootNode = g_pTreeCtrlPacketInfo->InsertItem(strText, TVI_ROOT);
	if (pkt.ethh != NULL)
	{
		printEthernet2TreeCtrl(pkt, rootNode);
	}

	g_pTreeCtrlPacketInfo->Expand(rootNode, TVE_EXPAND);
	return 0;
}

/**
*	@brief	打印以太网帧首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printEthernet2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.ethh == NULL || parentNode == NULL)
	{
		return -1;
	}
	/* 获取源目MAC地址 */
	CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
	CString	strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);
	CString strEthType;
	strEthType.Format("0x%04X", ntohs(pkt.ethh->eth_type));

	HTREEITEM	EthNode = g_pTreeCtrlPacketInfo->InsertItem( "以太网 （" + strSrcMAC + " -> " + strDstMAC + "）", parentNode, 0);

	g_pTreeCtrlPacketInfo->InsertItem("目的MAC地址：" + strDstMAC, EthNode, 0);
	g_pTreeCtrlPacketInfo->InsertItem("源MAC地址：" + strSrcMAC, EthNode, 0);
	g_pTreeCtrlPacketInfo->InsertItem("类型：" + strEthType, EthNode, 0);

	if (pkt.iph != NULL)
	{
		printIP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.arph != NULL)
	{
		printARP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

/**
*	@brief	打印IP首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printIP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.iph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM IPNode = g_pTreeCtrlPacketInfo->InsertItem("IP （" + IPAddr2CString(pkt.iph->srcaddr) + " -> " + IPAddr2CString(pkt.iph->dstaddr) + "）", parentNode, 0);
	CString strText;

	strText.Format("版本号：%d", pkt.iph->ver_headerlen >> 4);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText.Format("首部长度：%d 字节 (%d)", (pkt.iph->ver_headerlen & 0x0f) * 4, pkt.iph->ver_headerlen & 0x0f);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText.Format("服务质量：0x%02x", pkt.iph->tos);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText.Format("总长度：%hu", ntohs(pkt.iph->totallen));
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText.Format("标识：0x%04hX(%hu)", ntohs(pkt.iph->identifier), ntohs(pkt.iph->identifier));
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
				
	strText.Format("标志：0x%02x", ntohs(pkt.iph->flags_offset) >> 13);
	HTREEITEM IPFlagNode = g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText = "RSV：0";
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPFlagNode, 0);
	
	strText.Format("MF：%d", (ntohs(pkt.iph->flags_offset) >> 14) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPFlagNode, 0);
	
	strText.Format("DF：%d", (ntohs(pkt.iph->flags_offset) >> 13) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPFlagNode, 0);
			
	strText.Format("片偏移：%d", ntohs(pkt.iph->flags_offset) & 0x1fff);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText.Format("TTL：%u", pkt.iph->ttl);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	switch(pkt.iph->protocol)
	{
	case PROTOCOL_ICMP:	
		strText = "协议：ICMP (1)";
		break;
	case PROTOCOL_TCP:	
		strText = "协议：TCP (6)";
		break;
	case PROTOCOL_UDP: 
		strText = "协议：UDP (17)";
		break;
	default: 
		strText.Format("协议：未知 (%d)", pkt.iph->protocol);
		break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText.Format("校验和：0x%02hX", ntohs(pkt.iph->checksum));
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText = "源IP地址：" + IPAddr2CString(pkt.iph->srcaddr);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	strText = "目的IP地址：" + IPAddr2CString(pkt.iph->dstaddr);
	g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
	
	if (pkt.icmph != NULL)
	{
		printICMP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.tcph != NULL)
	{
		printTCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.udph != NULL)
	{
		printUDP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

/**
*	@brief	打印ARP首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printARP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.arph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM ARPNode;
	CString strText, strTmp;

	switch(ntohs(pkt.arph->opcode))
	{
	case 1:	strText.Format("ARP （请求)"); break;
	case 2:	strText.Format("ARP （响应)");	break;
	}	
	ARPNode= g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
	
	strText.Format("硬件类型：%hu", ntohs(pkt.arph->hwtype));
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	strText.Format("协议类型：0x%04hx (%hu)", ntohs(pkt.arph->ptype), ntohs(pkt.arph->ptype));
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	strText.Format("硬件地址长度：%u", pkt.arph->hwlen);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	strText.Format("协议地址长度：%u", pkt.arph->plen);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	switch(ntohs(pkt.arph->opcode))
	{
	case ARP_OPCODE_REQUET:	strText.Format("OP码：请求 (%hu)", ntohs(pkt.arph->opcode));
		break;
	case ARP_OPCODE_REPLY:	strText.Format("OP码：响应 (%hu)", ntohs(pkt.arph->opcode));
		break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	strText = "源MAC地址：" + MACAddr2CString(pkt.arph->srcmac);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	strText = "源IP地址：" + IPAddr2CString(pkt.arph->srcip);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
			
	strText = "目的MAC地址：" + MACAddr2CString(pkt.arph->dstmac);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	strText = "目的IP地址：" + IPAddr2CString(pkt.arph->dstip);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ARPNode, 0);
	
	return 0;
}

/**
*	@brief	打印ICMP首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printICMP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.icmph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM ICMPNode;
	CString strText, strTmp;
	
	strText = "ICMP （";
	switch(pkt.icmph->type)
	{
		case ICMP_TYPE_ECHO_REPLY: 
			strTmp = "回应应答报告"; 
			break;
		case ICMP_TYPE_DESTINATION_UNREACHABLE: 
			strTmp = "信宿不可达报告"; 
			break;
		case ICMP_TYPE_SOURCE_QUENCH: 
			strTmp = "源端抑制报告"; 
			break;
		case ICMP_TYPE_REDIRECT: 
			strTmp = "重定向报告"; 
			break;
		case ICMP_TYPE_ECHO: 
			strTmp = "回应请求报告"; 
			break;
		case ICMP_TYPE_ROUTER_ADVERTISEMENT: 
			strTmp = "路由器通告报告"; 
			break;
		case ICMP_TYPE_ROUTER_SOLICITATION: 
			strTmp = "路由器询问报告";
			break;
		case ICMP_TYPE_TIME_EXCEEDED: 
			strTmp = "超时报告"; 
			break;
		case ICMP_TYPE_PARAMETER_PROBLEM: 
			strTmp = "数据报参数错误报告"; 
			break;
		case ICMP_TYPE_TIMESTAMP: 
			strTmp = "时间戳请求报告"; 
			break;
		case ICMP_TYPE_TIMESTAMP_REPLY: 
			strTmp = "时间戳响应报告"; 
			break;
		default: 
			strText.Format("未知"); 
			break;
	}
	strText += strTmp + "）";
	ICMPNode = g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);
	
	IP_Address addr = *(IP_Address*)&(pkt.icmph->others);
	u_short id = (u_short)(ntohl(pkt.icmph->others) >> 16);
	u_short seq = (u_short)(ntohl(pkt.icmph->others) & 0x0000ffff);
	
	strText.Format("类型：%u", pkt.icmph->type);
	g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);

	switch(pkt.icmph->type)
	{
		case ICMP_TYPE_ECHO_REPLY:
			strText = "代码：0";
			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);

			strText.Format("校验和:0x%04hX", ntohs(pkt.icmph->chksum));
			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);

			strText.Format("标识：%hu", id);
			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);

			strText.Format("序号：%hu", seq);
			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);

			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE: 
			strText = "代码：";
			switch(pkt.icmph->code)
			{
				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE: 
					strText.Format("网络不可达 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE: 
					strText.Format("主机不可达 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE: 
					strText.Format("协议不可达 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE: 
					strText.Format("端口不可达 （%d）", pkt.icmph->code);
					break;

				case 6: 
					strTmp = "信宿网络未知 （6）"; 
					break;

				case 7: 
					strTmp = "信宿主机未知 （7）"; 
					break;

				default: 
					strText.Format("未知 （%d）", pkt.icmph->code); break;
			}
			strText += strTmp;
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
	
			strText.Format("校验和：0x%04hX", ntohs(pkt.icmph->chksum));
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
			break;
	
		case ICMP_TYPE_SOURCE_QUENCH : 
			strText.Format("代码：%d", ICMP_TYPE_SOURCE_QUENCH_CODE);
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
				
			strText.Format("校验和：0x%04hX", ntohs(pkt.icmph->chksum));
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
			break;
	
		case ICMP_TYPE_REDIRECT: 
				strText = "代码：";
				switch(pkt.icmph->code)
				{
				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK:	
					strText.Format("对特定网络重定向（%d)", pkt.icmph->code);
					break;

				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST: 
					strText.Format("对特定主机重定向 （%d)", pkt.icmph->code);
					break;

				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK: 
					strText.Format("基于指定的服务类型对特定网络重定向 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST: 
					strText.Format("基于指定的服务类型对特定主机重定向 （%d）", pkt.icmph->code); 
					break;
				}
				strText += strTmp;
				g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
	
				strText.Format("校验和：0x%04hx", ntohs(pkt.icmph->chksum));
				g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
	
				strText = "目标路由器的IP地址：" + IPAddr2CString(addr);
				g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
				break;

		case ICMP_TYPE_ECHO:
			strText.Format("代码：%d", pkt.icmph->code);
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);

			strText.Format("校验和：0x%04hX", ntohs(pkt.icmph->chksum));
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);

			strText.Format("标识：%hu", id);
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);

			strText.Format("序号：%hu", seq);
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
			break;

		case ICMP_TYPE_TIME_EXCEEDED: 
			strText = "代码：";
			switch(pkt.icmph->code)
			{
				case ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT: 
					strText.Format("TTL超时 （%d）", pkt.icmph->code);	
					break;
				case ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE: 
					strText.Format("分片重组超时 （%d）", pkt.icmph->code);
					break;
			}
			strText += strTmp;
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
	
			strText.Format("校验和：0x%04hx", ntohs(pkt.icmph->chksum));
			g_pTreeCtrlPacketInfo->InsertItem(strText, ICMPNode, 0);
	
			break;
	
		default: 
			strText.Format("代码：%d", pkt.icmph->code);
			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);

			strText.Format("校验和：0x%04hX", pkt.icmph->chksum);
			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);

			break;
		}
	return 0;
}

/**
*	@brief	打印TCP首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printTCP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.tcph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM TCPNode;
	CString strText, strTmp;
							
	strText.Format("TCP （%hu -> %hu）", ntohs(pkt.tcph->srcport), ntohs(pkt.tcph->dstport));
	TCPNode = g_pTreeCtrlPacketInfo->InsertItem(strText,parentNode, 0);
							
	strText.Format("源端口：%hu", ntohs(pkt.tcph->srcport));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("目的端口：%hu", ntohs(pkt.tcph->dstport));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("序列号：0x%0lX", ntohl(pkt.tcph->seq));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("确认号：0x%0lX", ntohl(pkt.tcph->ack));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("首部长度：%d 字节(%d)", (ntohs(pkt.tcph->headerlen_rsv_flags) >> 12 ) * 4, ntohs(pkt.tcph->headerlen_rsv_flags) >> 12);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("标志：0x%03X", ntohs(pkt.tcph->headerlen_rsv_flags) & 0x0FFF);
	HTREEITEM TCPFlagNode = g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("URG：%d", (ntohs(pkt.tcph->headerlen_rsv_flags) >> 5) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPFlagNode, 0);
							
	strText.Format("ACK：%d", (ntohs(pkt.tcph->headerlen_rsv_flags) >> 4) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPFlagNode, 0);
							
	strText.Format("PSH：%d", (ntohs(pkt.tcph->headerlen_rsv_flags) >> 3) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPFlagNode, 0);
							
	strText.Format("RST：%d", (ntohs(pkt.tcph->headerlen_rsv_flags) >> 2) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPFlagNode, 0);

	strText.Format("SYN：%d", (ntohs(pkt.tcph->headerlen_rsv_flags) >> 1) & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPFlagNode, 0);
							
	strText.Format("FIN：%d", ntohs(pkt.tcph->headerlen_rsv_flags)  & 0x0001);
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPFlagNode, 0);
							 
	strText.Format("窗口大小：%hu", ntohs(pkt.tcph->win_size));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("校验和：0x%04hX", ntohs(pkt.tcph->chksum));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);
							
	strText.Format("紧急指针：%hu", ntohs(pkt.tcph->urg_ptr));
	g_pTreeCtrlPacketInfo->InsertItem(strText, TCPNode, 0);

	if (pkt.dnsh != NULL)
	{
		printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcph != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.httpmsg != NULL)
	{
		printHTTP2TreeCtrl(pkt, parentNode);
	}


	return 0;
}

/**
*	@brief	打印UDP首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printUDP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.udph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM UDPNode;		
	CString strText, strTmp;
							
	strText.Format("UDP （%hu -> %hu）", ntohs(pkt.udph->srcport), ntohs(pkt.udph->dstport));
	UDPNode = g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);
							
	strText.Format("源端口：%hu", ntohs(pkt.udph->srcport));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);
							
	strText.Format("目的端口：%hu", ntohs(pkt.udph->dstport));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);
							
	strText.Format("长度：%hu", ntohs(pkt.udph->len));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);
							
	strText.Format("校验和：0x%04hX", ntohs(pkt.udph->checksum));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);

	if (pkt.dnsh != NULL)
	{
		printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcph != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}

/** 
*	@brief	打印DNS结点标题
*	@param	pkt	数据包
*	@param	parentNode 父节点
*	@return DNS结点
*/
HTREEITEM printDNSBanner(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || parentNode == NULL)
	{
		return NULL;
	}
	CString strText, strTmp;

	switch (pkt.dnsh->flags >> 15)
	{
	case DNS_FLAGS_QR_REQUEST:	strText = "DNS （请求）";		break;
	case DNS_FLAGS_QR_REPLY:	strText = "DNS （响应）";		break;
	}
	return g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);
}


/**
*	@brief	打印DNS首部
*	@param	dnsh	DNS首部
*	@param	parentNode	父节点
*	@return 0 打印成功	-1 打印失败
*/
int printDNSHeader(const DNS_Header *dnsh, HTREEITEM & parentNode)
{
	if (dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	strText.Format("标识：0x%04hX (%hu)", ntohs(dnsh->identifier), ntohs(dnsh->identifier));
	g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);

	strText.Format("标志：0x%04hX", ntohs(dnsh->flags));
	strText += strTmp;

	HTREEITEM DNSFlagNode = g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);
	/* 标志子字段 */
	switch (ntohs(dnsh->flags) >> 15)
	{
	case DNS_FLAGS_QR_REQUEST:	strText = "QR：; 查询报文 （0）";	break;
	case DNS_FLAGS_QR_REPLY:	strText = "QR：; 响应报文 （1）";	break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);

	switch ((ntohs(dnsh->flags) >> 11) & 0x000f)
	{
	case DNS_FLAGS_OPCODE_STANDARD_QUERY:			strText = "Opcode：标准查询 （0）";	break;
	case DNS_FLAGS_OPCODE_INVERSE_QUERY:			strText = "Opcode：反向查询 （1）";	break;
	case DNS_FLAGS_OPCODE_SERVER_STATUS_REQUEST:	strText = "Opcode：服务器状态请求 （2）"; break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);

	switch ((ntohs(dnsh->flags) >> 10) & 0x0001)
	{
	case 0:	strText = "AA：非授权回答 （0）"; break;
	case 1: strText = "AA：授权回答 （1）"; break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);


	switch ((ntohs(dnsh->flags) >> 9) & 0x0001)
	{
	case 0: strText = "TC：报文未截断 （0）"; break;
	case 1: strText = "TC：报文截断 （1）";	break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);


	switch ((ntohs(dnsh->flags) >> 8) & 0x0001)
	{
	case 0: strText = "RD：0"; break;
	case 1: strText = "RD：希望进行递归查询 （1）";	break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);

	switch ((ntohs(dnsh->flags) >> 7) & 0x0001)
	{
	case 0: strText = "RA：服务器不支持递归查询 （0）"; break;
	case 1: strText = "RA：服务器支持递归查询 （1）";	break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);

	strText.Format("Reserved：%d", (ntohs(dnsh->flags) >> 4) & 0x0007);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);

	switch (ntohs(dnsh->flags) & 0x000f)
	{
	case 0: strText = "rCode：无差错 （0）";			break;
	case 1: strText = "rCode：格式差错 （1）";			break;
	case 2: strText = "rCode：DNS服务器问题 （2）";		break;
	case 3: strText = "rCode：域名不存在或出错 （3）";	break;
	case 4: strText = "rCode：查询类型不支持 （4）";	break;
	case 5: strText = "rCode：在管理上禁止 （5）";		break;
	default: strText.Format("rCode：保留（%d）", ntohs(dnsh->flags) & 0x000f);		break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DNSFlagNode, 0);

	strText.Format("查询记录数：%hu", ntohs(dnsh->questions));
	g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);

	strText.Format("回答记录数：%hu", ntohs(dnsh->answers));
	g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);

	strText.Format("授权回答记录数：%hu", ntohs(dnsh->authority));
	g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);

	strText.Format("附加信息记录数：%hu", ntohs(dnsh->additional));
	g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);

	return 0;
}

/**
*	@brief	打印DNS查询部分
*	@param	dnsq		查询部分
*	@param	questions	查询记录数
*	@param	parentNode	父节点
*	@return	0 打印成功	-1 打印失败	正整数 DNS查询部分总长度
*/
int printDNSQuery(char *DNSQuery, const u_short &questions, HTREEITEM &parentNode)
{
	if (DNSQuery == NULL && parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	HTREEITEM DNSQueryNode = g_pTreeCtrlPacketInfo->InsertItem("查询部分：", parentNode, 0);

	/* 查询部分 */
	int queryNum = 0, byteCounter = 0;
	char *p = DNSQuery;
	if (questions < 10)
	{
		while (queryNum < questions)
		{
			char *name1 = (char*)malloc(strlen(p) + 1);
			translateName(name1, p);

			/* 跳过域名字段 */
			while (*p)
			{
				++p;
				++byteCounter;
			}
			++p;
			++byteCounter;

			strText.Format("%s:", name1);

			DNS_Query *dnsq = (DNS_Query*)p;
			u_short	type, classes;

			type = ntohs(dnsq->type);
			classes = ntohs(dnsq->classes);

			switch (type)
			{
			case 1:	strTmp = "type A"; break;
			case 2:	strTmp = "type NS"; break;
			case 5: strTmp = "type CNAME"; break;
			case 6: strTmp = "type SOA"; break;
			case 12: strTmp = "type PTR"; break;
			case 15: strTmp = "type MX"; break;
			case 28: strTmp = "type AAAA"; break;
			case 255: strTmp = "type ANY"; break;
			default: strTmp.Format("type UNKNOWN(%hu)", type); break;
			}
			strText += strTmp + ", ";

			switch (classes)
			{
			case 1: strTmp = "class INTERNET"; break;
			case 2: strTmp = "class CSNET";	break;
			case 3: strTmp = "class COAS";	break;
			default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
			}
			strText += strTmp;

			g_pTreeCtrlPacketInfo->InsertItem(strText, DNSQueryNode, 0);

			/* 跳过查询类型和查询类字段 */
			p += sizeof(DNS_Query);
			byteCounter += sizeof(DNS_Query);
			queryNum++;
			free(name1);
		}// while
	}// if
	return p - DNSQuery + 1;
}

/**
*	@brief	打印DNS回答部分
*	@param	dnsa		回答部分
*	@param	answers		回答记录数
*	@param	parentNode	父节点
*	@return	0 打印成功	-1 打印失败	正整数 DNS回答部分总长度
*/
int printDNSAnswer(char *DNSAnswer, const u_short &answers, const DNS_Header *dnsh, HTREEITEM &parentNode)
{
	if (DNSAnswer == NULL || parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	HTREEITEM DNSAnswerNode = g_pTreeCtrlPacketInfo->InsertItem("回答部分：", parentNode, 0);

	int answerNum = 0, byteCounter = 0;
	char *p = DNSAnswer;
	/* 回答部分 */
	while (answerNum < answers)
	{
		/* 指向指针 */
		if (*p == 0xc0)
		{

			/* 指向偏移量
			++p;

			char *name = (char*)(pkt_data + offset + *(char*)p);			// 域名
			char *name1 = (char*)malloc(strlen(name)+1);


			translateName(name1, name);

			strText.Format("%s", name1);
			strText += "：";

			free(name1);
			*/

			char name[70];
			char name1[70];

			translateData(dnsh, name, p, 2);
			translateName(name1, name);

			strText.Format("%s：", name1);

			/* 指向偏移量 */
			++p;
			++byteCounter;


			/* 指向类型*/
			++p;
			++byteCounter;
			DNS_Answer *dnsa = (DNS_Answer*)p;

			u_short type = ntohs(dnsa->type);
			u_short classes = ntohs(dnsa->classes);
			u_long  ttl = ntohl(dnsa->ttl);

			switch (type)
			{
			case 1:	strTmp = "type A"; break;
			case 2:	strTmp = "type NS"; break;
			case 5: strTmp = "type CNAME"; break;
			case 6: strTmp = "type SOA"; break;
			case 12: strTmp = "type PTR"; break;
			case 15: strTmp = "type MX"; break;
			case 28: strTmp = "type AAAA"; break;
			case 255: strTmp = "type ANY"; break;
			default: strTmp.Format("type UNKNOWN(%hu)", type); break;
			}
			strText += strTmp + ", ";

			switch (classes)
			{
			case 1: strTmp = "class INTERNET"; break;
			case 2: strTmp = "class CSNET";	break;
			case 3: strTmp = "class COAS";	break;
			default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
			}
			strText += strTmp + ", ";

			strTmp.Format("TTL %lu", ttl);
			strText += strTmp + ", ";

			/* 指向资源数据长度 */
			p += sizeof(DNS_Answer);
			byteCounter += sizeof(DNS_Answer);
			u_short data_len = ntohs(*(u_short*)p);

			strTmp.Format("资源数据长度 %hu", data_len);
			strText += strTmp + ", ";

			/* 指向资源数据 */
			p += sizeof(u_short);
			byteCounter += sizeof(u_short);

			/* 查询类型为NS、CNAME、PTR的资源数据 */
			if (type == 2 || type == 5 || type == 12)
			{

				/* 资源数据为指针0xc0 + 偏移量*/
				if (*(char*)p == 0xC0)
				{
					/* 根据偏移量获取数据
					char *data = (char*)(pkt_data + offset + *(char*)(p+1));			// 域名
					char *data1 = (char*)malloc(strlen(data)+1);

					translateName(data1, data);

					strText.Format("%s", data1);
					strText += strTmp;

					free(data1);
					*/
					char data[70];
					char data1[70];

					translateData(dnsh, data, p, 2);
					translateName(data1, data);

					strText.Format("%s", data1);
					strText += strTmp;

				}
				/* 资源数据存在指针0xc0 + 偏移量 */
				else if (isNamePtr(p))
				{
					char data[70];
					char data1[70];

					translateData(dnsh, data, p, data_len);		// 去掉指针0xc0+偏移量
					translateName(data1, data);								// 去掉'.'

					strTmp.Format("%s", data1);
					strText += strTmp;
				}
				/* 资源数据中不存在指针0xc0 + 偏移量 */
				else
				{
					char *data = (char*)malloc(data_len);

					translateName(data, p);

					strTmp.Format("%s", data);
					strText += strTmp;
					free(data);

				}
			}
			/* 查询类型为A的资源数据 */
			else if (type == 1)
			{
				IP_Address data = *(IP_Address*)p;
				strText += IPAddr2CString(data);
			}

			g_pTreeCtrlPacketInfo->InsertItem(strText, DNSAnswerNode, 0);

			/* 跳过数据部分 */
			p += data_len;
			byteCounter += data_len;

		}// if
		answerNum++;
	}// while
	return byteCounter;
}


int printDNSAuthority(char *DNSAuthority, const u_short &authority, const DNS_Header *dnsh, HTREEITEM parentNode)
{
	CString strText, strTmp;
	HTREEITEM DNSAuthorityNode = g_pTreeCtrlPacketInfo->InsertItem("授权回答部分：", parentNode, 0);

	int authorityNum = 0, byteCounter = 0;;
	char *p = DNSAuthority;
	/* 授权回答部分 */
	while (authorityNum < authority)
	{
		/* 指向指针 */
		if (*p == 0xC0)
		{

			/* 指向偏移量
			++p;

			char *name = (char*)(pkt_data + offset + *(char*)p);			// 域名
			char *name1 = (char*)malloc(strlen(name)+1);
			translateName(name1, name);

			strText.Format("%s", name1);
			strText += "：";
			free(name1);
			*/
			char name[70];
			char name1[70];

			translateData(dnsh, name, p, 2);
			translateName(name1, name);

			strText.Format("%s", name1);
			strText += "：";

			/* 指向偏移量 */
			++p;
			++byteCounter;

			/* 指向类型*/
			++p;
			++byteCounter;
			DNS_Answer *dnsa = (DNS_Answer*)p;

			u_short type = ntohs(dnsa->type);
			u_short classes = ntohs(dnsa->classes);
			u_long  ttl = ntohl(dnsa->ttl);

			switch (type)
			{
			case 1:	strTmp = "type A"; break;
			case 2:	strTmp = "type NS"; break;
			case 5: strTmp = "type CNAME"; break;
			case 6: strTmp = "type SOA"; break;
			case 12: strTmp = "type PTR"; break;
			case 15: strTmp = "type MX"; break;
			case 28: strTmp = "type AAAA"; break;
			case 255: strTmp = "type ANY"; break;
			default: strTmp.Format("type UNKNOWN(%hu)", type); break;
			}
			strText += strTmp + ", ";

			switch (classes)
			{
			case 1: strTmp = "class INTERNET"; break;
			case 2: strTmp = "class CSNET";	break;
			case 3: strTmp = "class COAS";	break;
			default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
			}
			strText += strTmp + ", ";

			strTmp.Format("ttl %lu", ttl);
			strText += strTmp + ", ";

			/* 指向资源数据长度 */
			p += sizeof(DNS_Answer);
			byteCounter += sizeof(DNS_Answer);

			u_short data_len = ntohs(*(u_short*)p);

			strTmp.Format("len %hu", data_len);
			strText += strTmp + ", ";

			/* 指向资源数据 */
			p += sizeof(u_short);
			byteCounter += sizeof(u_short);

			/* 查询类型为NS、CNAME、PTR的资源数据 */
			if (type == 2 || type == 5 || type == 12)
			{

				/* 资源数据为指针0xc0 + 偏移量*/
				if (*(char*)p == 0xc0)
				{
					/* 根据偏移量获取数据
					char *data = (char*)(pkt_data + offset + *(char*)(p+1));			// 域名
					char *data1 = (char*)malloc(strlen(data)+1);
					translateName(data1, data);
					strTmp.Format("%s", data1);
					strText += strTmp;
					free(data1);
					*/

					char data[70];
					char data1[70];

					translateData(dnsh, data, p, 2);
					translateName(data1, data);

					strTmp.Format("%s", data1);
					strText += strTmp;
				}
				/* 资源数据存在指针0xc0 + 偏移量 */
				else if (isNamePtr(p))
				{
					char data[70];
					char data1[70];

					translateData(dnsh, data, p, data_len);		// 去掉指针0xc0+偏移量
					translateName(data1, data);								// 去掉'.'

					strTmp.Format("%s", data1);
					strText += strTmp;
				}
				/* 资源数据中不存在指针0xc0 + 偏移量 */
				else
				{
					char *data = (char*)malloc(data_len);

					translateName(data, p);

					strTmp.Format("%s", data);
					strText += strTmp;
					free(data);

				}
			}
			/* 查询类型为A的资源数据 */
			else if (type == 1)
			{
				IP_Address data = *(IP_Address*)p;

				strText += IPAddr2CString(data);
			}

			g_pTreeCtrlPacketInfo->InsertItem(strText, DNSAuthorityNode, 0);

			/* 跳过数据部分 */
			p += data_len;
			byteCounter += data_len;


		}// if
		authorityNum++;
	}
	return byteCounter;
}

/**
*	@brief	打印DNS附加信息部分
*	@param	dnsa		附加信息部分
*	@param	answers		附加信息记录数
*	@param	parentNode	父节点
*	@return	0 打印成功	-1 打印失败 正整数 DNS附加信息部分总长度
*/
int printDNSAdditional(char *DNSAdditional, const u_short &additional, const DNS_Header *dnsh, HTREEITEM &parentNode)
{
	if (DNSAdditional == NULL || parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	HTREEITEM DNSAdditionalNode = g_pTreeCtrlPacketInfo->InsertItem("附加信息部分：", parentNode, 0);

	int additionalNum = 0, byteCounter = 0;
	char *p = DNSAdditional;
	/* 附加信息部分 */
	while (additionalNum < additional)
	{

		/* 指向指针 */
		if (*(char*)p == 0xC0)
		{

			/* 指向偏移量
			++p;

			char *name = (char*)(pkt_data + offset + *(char*)p);			// 域名
			char *name1 = (char*)malloc(strlen(name)+1);

			translateName(name1, name);

			strText.Format("%s", name1);
			strText += "：";

			free(name1);
			*/
			char name[70];
			char name1[70];

			translateData(dnsh, name, p, 2);
			translateName(name1, name);

			strText.Format("%s", name1);
			strText += "：";

			/* 指向偏移量 */
			++p;
			++byteCounter;

			/* 指向类型*/
			++p;
			++byteCounter;
			DNS_Answer *dnsa = (DNS_Answer*)p;

			u_short type = ntohs(dnsa->type);
			u_short classes = ntohs(dnsa->classes);
			u_long  ttl = ntohl(dnsa->ttl);

			switch (type)
			{
			case 1:	strTmp = "type A"; break;
			case 2:	strTmp = "type NS"; break;
			case 5: strTmp = "type CNAME"; break;
			case 6: strTmp = "type SOA"; break;
			case 12: strTmp = "type PTR"; break;
			case 15: strTmp = "type MX"; break;
			case 28: strTmp = "type AAAA"; break;
			case 255: strTmp = "type ANY"; break;
			default: strText.Format("type UNKNOWN(%hu)", type); break;
			}
			strText += strTmp + ", ";

			switch (classes)
			{
			case 1: strTmp = "class INTERNET"; break;
			case 2: strTmp = "class CSNET";	break;
			case 3: strTmp = "class COAS";	break;
			default: strText.Format("class UNKNOWN(%hu)", classes); break;
			}
			strText += strTmp + ", ";

			strText.Format("ttl %lu", ttl);
			strText += strTmp + ", ";

			/* 指向资源数据长度 */
			p += sizeof(DNS_Answer);
			byteCounter += sizeof(DNS_Answer);

			u_short data_len = ntohs(*(u_short*)p);

			strText.Format("len %hu", data_len);
			strText += strTmp + ", ";

			/* 指向资源数据 */
			p += sizeof(u_short);
			byteCounter += sizeof(u_short);

			/* 查询类型为NS、CNAME、PTR的资源数据 */
			if (type == 2 || type == 5 || type == 12)
			{

				/* 资源数据为指针0xc0 + 偏移量*/
				if (*(char*)p == 0xc0)
				{
					/* 根据偏移量获取数据
					char *data = (char*)(pkt_data + offset + *(char*)(p+1));			// 域名
					char *data1 = (char*)malloc(strlen(data)+1);

					translateName(data1, data);

					strText.Format("%s", data1);
					strText += strTmp;

					free(data1);
					*/

					char data[70];
					char data1[70];

					translateData(dnsh, data, p, 2);
					translateName(data1, data);

					strText.Format("%s", data1);
					strText += strTmp;
				}
				/* 资源数据存在指针0xc0 + 偏移量 */
				else if (isNamePtr(p))
				{
					char data[70];
					char data1[70];

					translateData(dnsh, data, p, data_len);		// 去掉指针0xc0+偏移量
					translateName(data1, data);								// 去掉'.'

					strText.Format("%s", data1);
					strText += strTmp;
				}
				/* 资源数据中不存在指针0xc0 + 偏移量 */
				else
				{
					char *data = (char*)malloc(data_len);

					translateName(data, p);

					strText.Format("%s", data);
					strText += strTmp;
					free(data);

				}
			}
			/* 查询类型为A的资源数据 */
			else if (type == 1)
			{
				IP_Address data = *(IP_Address*)p;
				strText += IPAddr2CString(data);
			}

			g_pTreeCtrlPacketInfo->InsertItem(strText, DNSAdditionalNode, 0);

			/* 跳过数据部分 */
			p += data_len;
			byteCounter += data_len;

		}// if
		additionalNum++;
	}// while
	return byteCounter;
}

/**
*	@brief	打印DNS报文到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printDNS2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM DNSNode = printDNSBanner(pkt, parentNode);

	printDNSHeader(pkt.dnsh, DNSNode);


	char *DNSQuery = (char*)pkt.dnsh + DNS_HEADER_LENGTH;
	int DNSQueryLen = printDNSQuery(DNSQuery, ntohs(pkt.dnsh->questions), DNSNode);

	char *DNSAnswer = NULL, *DNSAuthority = NULL, *DNSAdditional = NULL;
	int DNSAnswerLen = 0, DNSAuthorityLen = 0;

	if (pkt.dnsh->answers > 0)
	{
		DNSAnswer = DNSQuery + DNSQueryLen;
		DNSAnswerLen = printDNSAnswer(DNSAnswer, ntohs(pkt.dnsh->answers), pkt.dnsh, DNSNode);
	}

	if (pkt.dnsh->authority > 0)
	{
		DNSAuthority = DNSAnswer + DNSAnswerLen;
		DNSAuthorityLen = printDNSAuthority(DNSAuthority, ntohs(pkt.dnsh->authority), pkt.dnsh, DNSNode);
	}
	

	if (pkt.dnsh->additional > 0)
	{
		DNSAdditional = DNSAuthority + DNSAuthorityLen;
		printDNSAdditional(DNSAdditional, ntohs(pkt.dnsh->additional), pkt.dnsh, DNSNode);
	}


	return 0;
}

/**
*	@brief	打印DHCP首部到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printDHCP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.dhcph == NULL || parentNode == NULL)
	{
		return -1;
	}

	HTREEITEM DHCPNode = g_pTreeCtrlPacketInfo->InsertItem("DHCP", parentNode, 0);
	CString strText, strTmp;
	/* 解析dhcp首部 */
	strText.Format("报文类型：%d", pkt.dhcph->op);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText.Format("硬件类型：%d", pkt.dhcph->htype);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText.Format("硬件地址长度：%d", pkt.dhcph->hlen);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

	strText.Format("跳数：%d",pkt.dhcph->hops);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText.Format("事务ID：0x%08lX", ntohl(pkt.dhcph->xid));
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText.Format("客户启动时间：%hu", ntohs(pkt.dhcph->secs));
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText.Format("标志：0x%04hX", ntohs(pkt.dhcph->flags));
	switch(ntohs(pkt.dhcph->flags) >> 15)
	{
	case DHCP_FLAGS_BROADCAST: strText += "（广播）"; break;
	case DHCP_FLAGS_UNICAST: strText += "（单播）"; break;
	}
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText = "客户机IP地址：" + IPAddr2CString(pkt.dhcph->ciaddr);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText = "你的（客户）IP地址：" + IPAddr2CString(pkt.dhcph->yiaddr);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText = "服务器IP地址：" + IPAddr2CString(pkt.dhcph->siaddr);;
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText = "网关IP地址：" + IPAddr2CString(pkt.dhcph->giaddr);
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	/*  解析dhcp首部剩余部分 */
	CString strChaddr;
	for (int i=0; i< 6; ++i)
	{
		strText.Format("%02X", pkt.dhcph->chaddr[i]);
		strChaddr += strTmp + "-";
	}
	strChaddr.Delete(strChaddr.GetLength() - 1, 1);

	strText = "客户机MAC地址：" + strChaddr;
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText = "服务器主机名：";
	strTmp.Format("%s", pkt.dhcph->snamer);
	strText += strTmp;
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	strText = "引导文件名：";
	strTmp.Format("%s", pkt.dhcph->file);
	strText += strTmp;
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	
	// 跳过引导文件名
	u_char *p = (u_char*)pkt.dhcph->file + 128;
	
	if(ntohl(*(u_long*)p) == 0x63825363)
	{
		strText = "Magic cookie: DHCP";
		g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);
	}
	
	// 跳过magic cookie
	p += 4;
	
	while(*p != 0xFF)
	{
		switch (*p)
		{
		case DHCP_OPTIONS_DHCP_MESSAGE_TYPE:
		{
			strText = "选项：（53）DHCP报文类型";
			switch (*(p + 2))
			{
			case 1: strText += "（Discover）"; break;
			case 2: strText += "（Offer）"; break;
			case 3: strText += "（Request）"; break;
			case 4: strText += "（Decline）"; break;
			case 5: strText += "（ACK）"; break;
			case 6: strText += "（NAK）"; break;
			case 7: strText += "（Release）"; break;
			case 8: strText += "（Inform）"; break;
			}
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			strText.Format("长度：%d", *(++p));
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			strText.Format("DHCP：%d", *(++p));
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			++p;
		}
			break;

		case DHCP_OPTIONS_REQUESTED_IP_ADDRESS:
		{
			strText = "选项：（50）请求IP地址";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			strText.Format("长度：%d", *(++p));
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *addr = (IP_Address*)(++p);
			strText = "地址：" + IPAddr2CString(*addr);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
			break;

		case DHCP_OPTIONS_IP_ADDRESS_LEASE_TIME:
		{
			strText = "选项：（51）IP地址租约时间";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			strText.Format("长度：%d", *(++p));
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			u_int time = *(++p);
			strText.Format("租约时间：%u", time);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
			break;

		case DHCP_OPTIONS_CLIENT_IDENTIFIER:
		{
			strText = "选项：（61）客户机标识";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			strText = "硬件类型：";
			if (*(++p) == 0x01)
			{
				strText += "以太网（0x01）";
				g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

				MAC_Address *addr = (MAC_Address*)(++p);
				strText = "客户机标识：" + MACAddr2CString(*addr);
				g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

				p += 6;
			}
			else
			{
				strText.Format("%d", *p);
				strText += strTmp;
				g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

				p += len;
			}
		}
			break;

		case DHCP_OPTIONS_VENDOR_CLASS_IDENTIFIER:
		{
			strText = "选项：（60）供应商类标识";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "供应商类标识：";
			for (; count < len; count++)
			{
				strText.Format("%c", *(++p));
				strText += strTmp;
			}
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
			break;

		case DHCP_OPTIONS_SERVER_IDENTIFIER:
		{
			strText = "选项：（54）服务器标识";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *addr = (IP_Address*)(++p);
			strText = "服务器标识：" + IPAddr2CString(*addr);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
			break;

		case DHCP_OPTIONS_SUBNET_MASK:
		{

		
			strText = "选项：（1）子网掩码";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *submask = (IP_Address*)(++p);
			strText = "子网掩码：" + IPAddr2CString(*submask);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
			break;

		case DHCP_OPTIONS_ROUTER_OPTION:
		{

		
			strText = "选项：（3）路由器";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			while (count < len)
			{
				IP_Address *addr = (IP_Address*)(++p);
				strText = "路由器：" + IPAddr2CString(*addr);
				g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
			break;

		case DHCP_OPTIONS_DOMAIN_NAME_SERVER_OPTION: 
		{
			strText = "选项：（6）DNS服务器";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			++p;
			while (count < len)
			{
				IP_Address *addr = (IP_Address*)(p);
				strText = "DNS服务器：" + IPAddr2CString(*addr);
				g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
			break;


		case DHCP_OPTIONS_HOST_NAME_OPTION:
		{
			strText = "选项：（12）主机名";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "主机名：";

			for (; count < len; count++)
			{
				strText.Format("%c", *(++p));
				strText += strTmp;
			}
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
			break;

		case DHCP_OPTIONS_PAD_OPTION:
			++p;
			break;

		default:
		{
			strTmp.Format("选项：（%d", *p);
			strText += strTmp + "）";
			HTREEITEM DHCPOptionNode = g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPOptionNode, 0);

			// 指向选项内容
			++p;

			// 跳过选项内容
			p += len;
		}
			break;
		}// switch 
	
	}// while
	strText = "选项：（255）结束";
	g_pTreeCtrlPacketInfo->InsertItem(strText, DHCPNode, 0);	 
		
	return 0;
}

/**
*	@brief	打印HTTP报文到树形控件
*	@param	pkt 数据包
*	@param	parentNode 父节点
*	@return	0 插入成功	-1 插入失败
*/
int printHTTP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	if (pkt.isEmpty() || pkt.httpmsg == NULL || parentNode == NULL)
	{
		return -1;
	}

	u_char *p = pkt.httpmsg;
	int HTTPMsgLen = pkt.getL4PayloadLength();
		
	CString strText;
	if (ntohs(pkt.tcph->dstport) == PORT_HTTP)
	{
		strText = "HTTP (请求)";
	}
	else if (ntohs(pkt.tcph->srcport) == PORT_HTTP)
	{
		strText = "HTTP (响应)";
	}
	HTREEITEM HTTPNode = g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);
	
	for(int count = 0; count < HTTPMsgLen; )
	{
		strText = "";
		while(*p != '\r')
		{
			strText += *p;
			++p;
			++count;
		}
		strText += "\\r\\n";
		g_pTreeCtrlPacketInfo->InsertItem(strText, HTTPNode, 0);
	
		p += 2;
		count += 2;
	}	
	return 0;
}

/**
*	@brief	将MAC地址转换成CString类字符串
*	@param	addr MAC地址
*	@return	CString类字符串
*/
CString MACAddr2CString(const MAC_Address &addr)
{
	CString strAddr, strTmp;

	for (int i = 0; i < 6; ++i)
	{
		strTmp.Format("%02X", addr.bytes[i]);
		strAddr += strTmp + "-";
	}
	strAddr.Delete(strAddr.GetLength() - 1, 1);

	return strAddr;
}

/**
*	@brief	将IP地址转换成CString类字符串
*	@param	addr IP地址
*	@return	CString类字符串
*/
CString IPAddr2CString(const IP_Address &addr)
{
	CString strAddr, strTmp;

	for (int i = 0; i < 4; ++i)
	{
		strTmp.Format("%d", addr.bytes[i]);
		strAddr += strTmp + ".";
	}
	strAddr.Delete(strAddr.GetLength() - 1, 1);

	return strAddr;
}

/**
*	@brief	点击列表，打印数据包首部解析结果到树形控件 
*	@param	
*	@return	-
*/
void CSnifferUIDlg::OnClickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	/* 获取选中行的行号 */
	int	selRow = g_pListCtrlPacketList->GetSelectionMark();
	if (selRow == -1)
	{
		return;
	}

	POSITION pos = g_packetLinkList.FindIndex(selRow);
	Packet &pkt = g_packetLinkList.GetAt(pos);

	printTreeCtrlPacketInfo(pkt, selRow);
	printEditCtrlPacketData(pkt);
}

/**
*	@brief	点击超链接打开Github
*	@param
*	@return -
*/
void CAboutDlg::OnNMClickSyslink1(NMHDR *pNMHDR, LRESULT *pResult)
{
	PNMLINK pNMLink = (PNMLINK)pNMHDR;
	ShellExecuteW(NULL, L"open", pNMLink->item.szUrl, NULL, NULL, SW_SHOWNORMAL);
	*pResult = 0;
}

/**
*	@brief	根据协议名给ListCtrl控件的Item填充底色
*	@param	-
*	@return	-
*/
void CSnifferUIDlg::OnCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;
	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if(CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) 
	{

		COLORREF itemColor;

		POSITION pos = g_packetLinkList.FindIndex(pNMCD->nmcd.dwItemSpec);
		Packet &pkt = g_packetLinkList.GetAt(pos);

		if (pkt.protocol == "ARP")
		{
			itemColor = RGB(255, 182, 193);
		}
		else if (pkt.protocol == "ICMP")
		{
			itemColor = RGB(186, 85, 211);
		}
		else if (pkt.protocol == "TCP")
		{
			itemColor = RGB(144, 238, 144);
		}
		else if (pkt.protocol == "UDP")
		{
			itemColor = RGB(100, 149, 237);

		}
		else if (pkt.protocol == "DNS")
		{
			itemColor = RGB(135, 206, 250);
		}
		else if (pkt.protocol == "DHCP")
		{
			itemColor = RGB(189, 254, 76);
		}
		else if (pkt.protocol == "HTTP")
		{
			itemColor = RGB(238, 232, 180);
		}
		else
		{
			itemColor = RGB(211, 211, 211);
		}

		pNMCD->clrTextBk = itemColor;
		*pResult = CDRF_DODEFAULT;
	}
}

void translateName(char *name1, const char *name2)
{
	strcpy(name1, name2);

	char *p = name1;
	bool canMove = false;

	if (!isalnum(*(u_char*)p) && *(u_char*)p != '-')
	{
		canMove = true;
	}

	/* 将计数转换为'.' */
	while (*p)
	{
		if (!isalnum(*(u_char*)p) && *(u_char*)p != '-')
			*p = '.';

		++p;
	}


	/* 将域名整体向前移1位 */
	if (canMove)
	{
		p = name1;
		while (*p)
		{
			*p = *(p + 1);
			++p;
		}
	}
}

/* DNS资源记录数据部分转换 将带有指针0xc0的data2转换为不带指针的data1 offset为到dns首部的偏移量*/
void translateData(const DNS_Header *dnsh, char *data1, char *data2, const int data2_len)
{
	char *p = data2;
	int count = 0, i = 0;

	/* 遍历data2 */
	while (count < data2_len)
	{
		/* 指针 */
		if (*(u_char*)p == 0xC0)
		{
			++p;

			/* 读取指针所指向的数据 */
			char *data_ptr = (char*)((u_char*)dnsh + *(u_char*)p);

			int pos = isNamePtr(data_ptr);
			if (pos)
			{
				translateData(dnsh, data1 + i, data_ptr, pos + 2);
			}
			else
			{
				strcpy(data1 + i, data_ptr);
				i += strlen(data_ptr) + 1;
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
/* 判断data中有无指针0xc0,并返回指针在data中的位置*/
int isNamePtr(char *data)
{
	char *p = data;
	int pos = 0;

	while (*p)
	{
		if (*(u_char*)p == 0xC0)
		{
			return pos;
		}
		++p;
		++pos;
	}

	return 0;
}