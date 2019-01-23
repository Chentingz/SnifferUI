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

	// BUG，链表里面存的pkt不对 
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
	CString strTmp;
	strTmp.Format("第%d个数据包", pktIndex + 1);

	HTREEITEM rootNode = g_pTreeCtrlPacketInfo->InsertItem(strTmp,TVI_ROOT);
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

	strText = "ARP （";
	switch(ntohs(pkt.arph->opcode))
	{
	case 1:	strTmp.Format("请求"); break;
	case 2:	strTmp.Format("响应");	break;
	}
	strText += strTmp + "）";		
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
			strTmp = "时间戳应答报告"; 
			break;
		default: 
			strTmp.Format("未知"); 
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
					strTmp.Format("网络不可达 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE: 
					strTmp.Format("主机不可达 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE: 
					strTmp.Format("协议不可达 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE: 
					strTmp.Format("端口不可达 （%d）", pkt.icmph->code);
					break;

				case 6: 
					strTmp = "信宿网络未知 （6）"; 
					break;

				case 7: 
					strTmp = "信宿主机未知 （7）"; 
					break;

				default: 
					strTmp.Format("未知 （%d）", pkt.icmph->code); break;
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
					strTmp.Format("对特定网络重定向（%d)", pkt.icmph->code);
					break;

				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST: 
					strTmp.Format("对特定主机重定向 （%d)", pkt.icmph->code);
					break;

				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK: 
					strTmp.Format("基于指定的服务类型对特定网络重定向 （%d）", pkt.icmph->code);
					break;

				case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST: 
					strTmp.Format("基于指定的服务类型对特定主机重定向 （%d）", pkt.icmph->code); 
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
					strTmp.Format("TTL超时 （%d）", pkt.icmph->code);	
					break;
				case ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE: 
					strTmp.Format("分片重组超时 （%d）", pkt.icmph->code);
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
							
	strText = "TCP （";
	strTmp.Format("%hu", ntohs(pkt.tcph->srcport));
	strText += strTmp + " -> ";
	strTmp.Format("%hu", ntohs(pkt.tcph->dstport));
	strText += strTmp + "）";
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
							
	strText.Format("标志：0x%03X", ntohs(pkt.tcph->headerlen_rsv_flags) & 0x0fff);
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
							
	strText = "UDP （";
	strTmp.Format("%hu", ntohs(pkt.udph->srcport));
	strText += strTmp + " -> ";
	strTmp.Format("%hu", ntohs(pkt.udph->dstport));
	strText += strTmp + "）";
	UDPNode = g_pTreeCtrlPacketInfo->InsertItem(strText, parentNode, 0);
							
	strText.Format("源端口：%hu", ntohs(pkt.udph->srcport));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);
							
	strTmp.Format("目的端口：%hu", ntohs(pkt.udph->dstport));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);
							
	strText.Format("长度：%hu", ntohs(pkt.udph->len));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);
							
	strText.Format("校验和：0x%04hX", ntohs(pkt.udph->checksum));
	g_pTreeCtrlPacketInfo->InsertItem(strText, UDPNode, 0);

	return 0;
}

int printDNS2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
	return 0;
}

int printDHCP2TreeCtrl(const Packet & pkt, HTREEITEM & parentNode)
{
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
	int HTTPMsgLen = ntohs(pkt.iph->totallen) - (pkt.iph->ver_headerlen & 0x0F) * 4 - (ntohs(pkt.tcph->headerlen_rsv_flags) >> 12)*4;
		
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

///* 存储以太网帧 */
//void saveFrame(const u_char *pkt_data, int offset)
//{
//	/* 获取以太网帧的类型字段、源目MAC地址 */
//	u_short eth_type = ntohs(*(u_short*)(pkt_data + 12));
//	mac_address *src_mac = (mac_address*)(pkt_data + 6);
//	mac_address *dst_mac = (mac_address*)(pkt_data);
//	
//	/* 将类型、源目MAC地址保存到链表的尾结点上 */
//	linklist.GetTail().saddr = *src_mac;
//	linklist.GetTail().daddr = *dst_mac;
//	linklist.GetTail().eth_type = eth_type;
//	
//	/* 根据以太网帧中类型字段存储报文 */
//	switch(eth_type)
//	{
//	case 0x0800: saveIP(pkt_data, 14); 
//					break;
//	case 0x0806: saveARP(pkt_data, 14); 
//					pList1->SetItemText(list_rows, ++list_cols, "ARP"); 
//					break;
//	default: break;
//	}
//	
//}
//
///* 存储IP包 */
//void saveIP(const u_char *pkt_data, int offset)				//offset为ip首部距离pkt_data的偏移量
//{
//	ip_header *ip_hdr = (ip_header*)(pkt_data + offset);
//
//	/* 存储ip首部到链表中 */
//	ip_header *p ;
//
//	p = (ip_header*)malloc(sizeof(ip_header));
//	p->ver_hrdlen = ip_hdr->ver_hrdlen;
//	p->tos = ip_hdr->tos;
//	p->totallen = ip_hdr->totallen;
//	p->identifier = ip_hdr->identifier;
//	p->flags_offset = ip_hdr->flags_offset;
//	p->ttl = ip_hdr->ttl;
//	p->proto = ip_hdr->proto;
//	p->checksum = ip_hdr->checksum;
//	p->option_padding = ip_hdr->option_padding;
//	p->srcaddr = ip_hdr->srcaddr;
//	p->dstaddr = ip_hdr->dstaddr;
//
//	linklist.GetTail().iph = p;
//
//	/* 根据上层协议存储报文首部 */
//	switch(ip_hdr->proto)
//	{
//	case 1:		saveICMP(pkt_data, offset + (ip_hdr->ver_hrdlen & 0x0f) * 4);
//				pList1->SetItemText(list_rows, ++list_cols, "ICMP"); 
//				break;	//ICMP
//
//	case 6:		saveTCP(pkt_data, offset + (ip_hdr->ver_hrdlen & 0x0f) * 4); 
//				break;	//TCP
//
//	case 17:	saveUDP(pkt_data, offset + (ip_hdr->ver_hrdlen & 0x0f) * 4); 
//				break;	//UDP
//
//	default:	pList1->SetItemText(list_rows, ++list_cols, "IPv4"); 
//				break;
//	}
//}
//
//
///* 存储ARP包 */
//void saveARP(const u_char *pkt_data, int offset)				//offset为ARP首部距离pkt_data的偏移量
//{
//	arp_header *arp_hdr = (arp_header*)(pkt_data + offset);
//
//	/* 存储arp首部到链表中 */
//	arp_header *p;
//
//	p = (arp_header*)malloc(sizeof(arp_header));
//	p->hardtype = arp_hdr->hardtype;
//	p->prototype = arp_hdr->prototype;
//	p->hardlen = arp_hdr->hardlen;
//	p->protolen = arp_hdr->protolen;
//	p->op = arp_hdr->op;
//	p->srcmac = arp_hdr->srcmac;
//	p->srcip = arp_hdr->srcip;
//	p->dstmac = arp_hdr->dstmac;
//	p->dstip = arp_hdr->dstip;
//
//	linklist.GetTail().arph = p;
//	
//}
//
///* 存储ICMP包*/
//void saveICMP(const u_char *pkt_data,int offset)
//{
//	icmp_header *icmp_hdr = (icmp_header*)(pkt_data + offset);
//
//	/* 存储icmp首部到链表中*/
//	icmp_header *p;
//
//	p = (icmp_header*)malloc(sizeof(icmp_header));
//	p->type = icmp_hdr->type;
//	p->code = icmp_hdr->code;
//	p->chksum = icmp_hdr->chksum;
//	p->others = icmp_hdr->others;
//
//	linklist.GetTail().icmph = p;
//}
//
//
//
//
//
///* 存储UDP包 */
//void saveUDP(const u_char *pkt_data, int offset)				//offset为UDP首部距离pkt_data的偏移量
//{
//	udp_header *udp_hdr = (udp_header*)(pkt_data + offset);
//
//	/* 存储udp首部到链表中 */
//	udp_header* p;
//
//	p = (udp_header*)malloc(sizeof(udp_header));
//	p->srcport = udp_hdr->srcport;
//	p->dstport = udp_hdr->dstport;
//	p->len = udp_hdr->len;
//	p->checksum = udp_hdr->checksum;
//
//	linklist.GetTail().udph = p;
//
//	/* 根据源目端口号存储报文首部 */
//	if(ntohs(udp_hdr->srcport) == 53 || ntohs(udp_hdr->dstport) == 53)
//	{
//		saveDNS(pkt_data, offset + 8);
//		pList1->SetItemText(list_rows, ++list_cols, "DNS"); 
//	}
//	else if( (ntohs(udp_hdr->srcport) == 67 && ntohs(udp_hdr->dstport) == 68) || (ntohs(udp_hdr->srcport) == 68 && ntohs(udp_hdr->dstport) == 67))
//	{
//		pList1->SetItemText(list_rows, ++list_cols, "DHCP"); 
//	}
//
//	else
//	{
//		pList1->SetItemText(list_rows, ++list_cols, "UDP"); 
//	}
//}
//
///* 存储TCP包 */
//void saveTCP(const u_char *pkt_data, int offset)
//{
//	tcp_header *tcp_hdr = (tcp_header*)(pkt_data + offset);
//
//	/* 存储tcp首部到链表中*/
//	tcp_header *p;
//
//	p = (tcp_header*)malloc(sizeof(tcp_header));
//	p->srcport = tcp_hdr->srcport;
//	p->dstport = tcp_hdr->dstport;
//	p->seq = tcp_hdr->seq;
//	p->ack = tcp_hdr->ack;
//	p->hdrlen_rsv_flags = tcp_hdr->hdrlen_rsv_flags;
//	p->win_size = tcp_hdr->win_size;
//	p->chksum = tcp_hdr->chksum;
//	p->urg_ptr = tcp_hdr->urg_ptr;
//	p->option = tcp_hdr->option;
//
//	linklist.GetTail().tcph = p;
//
//	/* 根据源目端口号存储报文首部 */
//	if(ntohs(tcp_hdr->srcport) == 53 || ntohs(tcp_hdr->dstport) == 53)
//	{
//		saveDNS(pkt_data, offset + (ntohs(tcp_hdr->hdrlen_rsv_flags) >> 12) * 4);
//		pList1->SetItemText(list_rows, ++list_cols, "DNS"); 
//	}
//
//	else if(ntohs(tcp_hdr->srcport) == 80 || ntohs(tcp_hdr->dstport) == 80)
//	{	
//		pList1->SetItemText(list_rows, ++list_cols, "HTTP"); 
//	}
//
//	else
//	{
//		pList1->SetItemText(list_rows, ++list_cols, "TCP"); 
//	}
//	
//}
//
///* 存储DNS */
//void saveDNS(const u_char *pkt_data, int offset)
//{
//	dns_header *dns_hdr = (dns_header*)(pkt_data + offset);
//
//	/* 存储dns首部到链表中 */
//	dns_header *p;
//	p = (dns_header*)malloc(sizeof(dns_header));
//	p->identifier = dns_hdr->identifier;
//	p->flags = dns_hdr->flags;
//	p->questions = dns_hdr->questions;
//	p->answers = dns_hdr->answers;
//	p->authority = dns_hdr->authority;
//	p->additional = dns_hdr->additional;
//
//	linklist.GetTail().dnsh = p;
//}
//
///* 解析以太网帧 */
//void decodeFrame(mac_address *saddr, mac_address *daddr, u_short *eth_type, HTREEITEM parentNode)
//{
//	HTREEITEM hFrameItem;		//树形控件结点
//	CString strText, strTmp;
//
//	strText = "以太网帧 （";
////	strTmp.Format("%02X-%02X-%02X-%02X-%02X-%02X", saddr->byte1, saddr->byte2, saddr->byte3, saddr->byte4, saddr->byte5, saddr->byte6);
//	strText += strTmp + " -> ";
////	strTmp.Format("%02X-%02X-%02X-%02X-%02X-%02X", daddr->byte1, daddr->byte2, daddr->byte3, daddr->byte4, daddr->byte5, daddr->byte6);
//	strText += strTmp + "）";
//	hFrameItem = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//	
//	
//	strText = "源mac地址：";
////	strTmp.Format("%02X-%02X-%02X-%02X-%02X-%02X", saddr->byte1, saddr->byte2, saddr->byte3, saddr->byte4, saddr->byte5, saddr->byte6);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hFrameItem, 0);
//
//	strText = "目的mac地址：";
////	strTmp.Format("%02X-%02X-%02X-%02X-%02X-%02X", daddr->byte1, daddr->byte2, daddr->byte3, daddr->byte4, daddr->byte5, daddr->byte6);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hFrameItem, 0);
//
//	strText = "类型：";
//	switch(*eth_type)
//	{
//	case 0x0800: strTmp = "IPv4 (0x0800)"; break;
//	case 0x0806: strTmp = "ARP (0x0806)"; break;
//	default: strTmp.Format("Unknown(0x%04hx)", *eth_type);	break;
//	}
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hFrameItem, 0);
//
//}
//
///* 解析IP  */
//void decodeIP(ip_header *iph,HTREEITEM parentNode)
//{
//		HTREEITEM IPNode;		//树形控件结点
//		CString strText, strTmp;
//
//		strText = "IP （";
////		strTmp.Format("%d.%d.%d.%d", iph->srcaddr.byte1, iph->srcaddr.byte2, iph->srcaddr.byte3, iph->srcaddr.byte4);
//		strText += strTmp + " -> ";
////		strTmp.Format("%d.%d.%d.%d", iph->dstaddr.byte1, iph->dstaddr.byte2, iph->dstaddr.byte3, iph->dstaddr.byte4);
//		strText += strTmp + "）";
//		IPNode = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//		strText = "版本号：";
////		strTmp.Format("%d", iph->ver_hrdlen >> 4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//		strText = "首部长度：";
////		strTmp.Format("%d (bytes)", (iph->ver_hrdlen & 0x0f) * 4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//		strText = "服务质量：";
//		strTmp.Format("0x%02x", iph->tos);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
//
//		strText = "总长度： ";
//		strTmp.Format("%hu", ntohs(iph->totallen));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
//
//		strText = "标识：";
//		strTmp.Format("0x%04hx(%hu)", ntohs(iph->identifier), ntohs(iph->identifier));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
//			
//
//		strText = "标志：";
//		strTmp.Format("0x%02x", ntohs(iph->flags_offset) >> 13);
//		strText += strTmp;
//		HTREEITEM hIPFlag = g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
//
//		strText = "RSV（保留位）：0";
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hIPFlag, 0);
//
//		strText = "MF：";
//		strTmp.Format("%d", (ntohs(iph->flags_offset) >> 14) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hIPFlag, 0);
//
//		strText = "DF：";
//		strTmp.Format("%d", (ntohs(iph->flags_offset) >> 13) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hIPFlag, 0);
//
//
//		
//		
//		strText = "片偏移：";
//		strTmp.Format("%d", ntohs(iph->flags_offset) & 0x1fff);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, IPNode, 0);
//
//		strText = "TTL：";
//		strTmp.Format("%u", iph->ttl);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//		//strText = "协议：";
//		//switch(iph->proto)
//		//{
//		//case 1:	strTmp = "ICMP (1)"; break;
//		//case 6:	strTmp = "TCP (6)"; break;
//		//case 17: strTmp = "UDP (17)"; break;
//		//default: strTmp.Format("UNKNOWN(%d)", iph->proto);	break;
//		//}
//
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//		strText = "校验和：";
//		strTmp.Format("0x%02hx", ntohs(iph->checksum));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//		strText = "源ip地址：";
////		strTmp.Format("%d.%d.%d.%d", iph->srcaddr.byte1, iph->srcaddr.byte2, iph->srcaddr.byte3, iph->srcaddr.byte4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//		strText = "目的ip地址：";
////		strTmp.Format("%d.%d.%d.%d", iph->dstaddr.byte1, iph->dstaddr.byte2, iph->dstaddr.byte3, iph->dstaddr.byte4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, IPNode, 0);
//
//}
//
///* 解析ARP */
//void decodeARP(arp_header *arph, HTREEITEM parentNode)
//{
//	HTREEITEM hARPItem;			//树形控件结点
//	CString strText, strTmp;
//
//	strText = "ARP （";
//	/*	switch(ntohs(arph->op))
//		{
//		case 1:	strTmp.Format("Request"); break;
//		case 2:	strTmp.Format("Reply");	break;
//		}*/
//		strText += strTmp + "）";		
//		ARPNode= g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//		strText = "硬件类型：";
////		strTmp.Format("%hu", ntohs(arph->hardtype), ntohs(arph->hardtype));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "协议类型：";
////		strTmp.Format("0x%04hx (%hu)", ntohs(arph->prototype), ntohs(arph->prototype));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "硬件地址长度：";
////		strTmp.Format("%u", arph->hardlen);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "协议地址长度：";
////		strTmp.Format("%u", arph->protolen);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "OP：";
////		switch(ntohs(arph->op))
//		{
////		case 1:	strTmp.Format("0x%04hx (Request)", ntohs(arph->op)); break;
////		case 2:	strTmp.Format("0x%04hx (Reply)", ntohs(arph->op));	break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "源mac地址：";
////		strTmp.Format("%02X-%02X-%02X-%02X-%02X-%02X", arph->srcmac.byte1, arph->srcmac.byte2, arph->srcmac.byte3, arph->srcmac.byte4, arph->srcmac.byte5, arph->srcmac.byte1);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "源ip地址：";
////		strTmp.Format("%d.%d.%d.%d", arph->srcip.byte1, arph->srcip.byte2, arph->srcip.byte3, arph->srcip.byte4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//		
//		strText = "目的mac地址：";
////		strTmp.Format("%02X-%02X-%02X-%02X-%02X-%02X", arph->dstmac.byte1, arph->dstmac.byte2, arph->dstmac.byte3, arph->dstmac.byte4, arph->dstmac.byte5, arph->dstmac.byte1);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//		strText = "目的ip地址：";
////		strTmp.Format("%d.%d.%d.%d", arph->dstip.byte1, arph->dstip.byte2, arph->dstip.byte3, arph->dstip.byte4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hARPItem, 0);
//
//}
//
///* 解析ICMP */
//void decodeICMP(icmp_header *icmph, HTREEITEM parentNode)
//{
//	HTREEITEM ICMPNode;
//	CString strText, strTmp;
//
//	strText = "ICMP （";
//
//	switch(icmph->type)
//	{
//		case 0: strTmp = "回应应答报告"; break;
//		case 3: strTmp = "信宿不可达报告"; break;
//		case 4: strTmp = "源端抑制报告"; break;
//		case 5: strTmp = "重定向报告"; break;
//		case 8: strTmp = "回应请求报告"; break;
//		case 9: strTmp = "路由器通告报告"; break;
//		case 10: strTmp = "路由器询问报告"; break;
//		case 11: strTmp = "超时报告"; break;
//		case 12: strTmp = "数据报参数错误报告"; break;
//		case 13: strTmp = "时间戳请求报告"; break;
//		case 14: strTmp = "时间戳应答报告"; break;
//		case 17: strTmp = "地址掩码请求报告"; break;
//		case 18: strTmp = "地址掩码应答报告"; break;
//		default: strTmp.Format("UNKNOWN（%d）", icmph->type); break;
//	}
//
//	strText += strTmp + "）";
//
//	ICMPNode = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//	ip_address *addr = (ip_address*)(&(icmph->others));
//
//	u_short id = (u_short)(ntohl(icmph->others) >> 16);
//	u_short seq = (u_short)(ntohl(icmph->others) & 0x0000ffff);
//
//	strText = "类型：";
//	switch(icmph->type)
//	{
//	case 3: strTmp = "3"; 
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "代码：";
//			switch(icmph->code)
//			{
//			case 0: strTmp = "0 （网络不可达）"; break;
//			case 1: strTmp = "1 （主机不可达）"; break;
//			case 2: strTmp = "2 （协议不可达）"; break;
//			case 3: strTmp = "3 （端口不可达）"; break;
//			case 6: strTmp = "6 （信宿网络未知）"; break;
//			case 7: strTmp = "7 （信宿主机未知）"; break;
//			default: strTmp.Format("%d （UNKNOWN）", icmph->code); break;
//			}
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "校验和：";
//			strTmp.Format("0x%04hx", ntohs(icmph->chksum));
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			break;
//
//	case 4: strTmp = "4";
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "代码：0 ";
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//			
//			strText = "校验和：";
//			strTmp.Format("0x%04hx", ntohs(icmph->chksum));
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//			break;
//
//	case 5: strTmp = "5";
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "代码：";
//			switch(icmph->code)
//			{
//			case 0:	strTmp = "0 （对特定网络重定向）"; break;
//			case 1: strTmp = "1 （对特定主机重定向）"; break;
//			case 2: strTmp = "2 （基于指定的服务类型对特定网络重定向）";break;
//			case 3: strTmp = "3 （基于指定的服务类型对特定主机重定向）"; break;
//			}
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "校验和：";
//			strTmp.Format("0x%04hx", ntohs(icmph->chksum));
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//
//			strText = "目标路由器的IP地址：";
//			strTmp.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//			break;
//
//	case 11: strTmp = "11"; 
//			 strText += strTmp;
//			 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			 strText = "代码：";
//			 switch(icmph->code)
//			 {
//			 case 0: strTmp = "0 （TTL超时）";	break;
//			 case 1: strTmp = "1 （分片重组超时）"; break;
//			 }
//			 strText += strTmp;
//			 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "校验和：";
//			strTmp.Format("0x%04hx", ntohs(icmph->chksum));
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			 break;
//
//	case 8: strTmp = "8";
//			 strText += strTmp;
//			 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "代码：0";
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "校验和：";
//			strTmp.Format("0x%04hx", ntohs(icmph->chksum));
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "标识：";
//			strTmp.Format("%hu", id);
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "序号：";
//			strTmp.Format("%hu", seq);
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			break;
//
//	case 0:	strTmp = "0";
//			strText += strTmp;
//		    g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "代码：0";
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "校验和：";
//			strTmp.Format("0x%04hx", ntohs(icmph->chksum));
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "标识：";
//			strTmp.Format("%hu", id);
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			strText = "序号：";
//			strTmp.Format("%hu", seq);
//			strText += strTmp;
//			g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			break;
//
//	default: strTmp.Format("%d", icmph->type);
//			 strText += strTmp;
//			 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//
//			 strText = "代码：";
//			 strTmp.Format("%d", icmph->code);
//
//			 strText = "校验和：";
//			 strTmp.Format("0x%04hx", icmph->chksum);
//			 strText += strTmp;
//			 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, ICMPNode, 0);
//			 break;
//	}
//}
//
//
///* 解析UDP */
//void decodeUDP(udp_header *udph, HTREEITEM parentNode)
//{
//		HTREEITEM hUDPItem;		//树形控件结点
//		CString strText, strTmp;
//
//		strText = "UDP （";
//		strTmp.Format("%hu", ntohs(udph->srcport));
//		strText += strTmp + " -> ";
//		strTmp.Format("%hu", ntohs(udph->dstport));
//		strText += strTmp + "）";
//		hUDPItem = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//		strText = "源端口：";
//		strTmp.Format("%hu", ntohs(udph->srcport));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hUDPItem, 0);
//
//		strText = "目的端口：";
//		strTmp.Format("%hu", ntohs(udph->dstport));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hUDPItem, 0);
//
//		strText = "长度：";
//		strTmp.Format("%hu", ntohs(udph->len));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hUDPItem, 0);
//
//		strText = "校验和：";
//		strTmp.Format("0x%04hx", ntohs(udph->checksum));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hUDPItem, 0);
//
//}
//
///* 解析TCP */
//void decodeTCP(tcp_header *tcph, HTREEITEM parentNode)
//{
//		HTREEITEM hTCPItem;		//树形控件结点
//		CString strText, strTmp;
//
//		strText = "TCP （";
//		strTmp.Format("%d", ntohs(tcph->srcport));
//		strText += strTmp + " -> ";
//		strTmp.Format("%d", ntohs(tcph->dstport));
//		strText += strTmp + "）";
//		hTCPItem = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//		strText = "源端口：";
//		strTmp.Format("%hu", ntohs(tcph->srcport));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hTCPItem, 0);
//
//		strText = "目的端口：";
//		strTmp.Format("%hu", ntohs(tcph->dstport));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hTCPItem, 0);
//
//		strText = "序列号：";
//		strTmp.Format("%lu", ntohl(tcph->seq));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hTCPItem, 0);
//
//		strText = "确认号：";
//		strTmp.Format("%lu", ntohl(tcph->ack));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,  hTCPItem, 0);
//
//		strText = "首部长度：";
//		strTmp.Format("%d (bytes)", (ntohs(tcph->hdrlen_rsv_flags) >> 12 ) * 4);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,  hTCPItem, 0);
//
//		strText = "标志：";
//		strTmp.Format("0x%03x", ntohs(tcph->hdrlen_rsv_flags) & 0x0fff);
//		strText += strTmp;
//		HTREEITEM hTCPFlag = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,  hTCPItem, 0);
//
//		strText = "URG：";
//		strTmp.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 5) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hTCPFlag, 0);
//
//		strText = "ACK：";
//		strTmp.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 4) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hTCPFlag, 0);
//
//		strText = "PSH：";
//		strTmp.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 3) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hTCPFlag, 0);
//
//		strText = "RST：";
//		strTmp.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 2) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hTCPFlag, 0);
//
//		strText = "SYN：";
//		strTmp.Format("%d", (ntohs(tcph->hdrlen_rsv_flags) >> 1) & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hTCPFlag, 0);
//
//		strText = "FIN：";
//		strTmp.Format("%d", ntohs(tcph->hdrlen_rsv_flags)  & 0x0001);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hTCPFlag, 0);
//
//		strText = "窗口大小：";
//		strTmp.Format("%hu", ntohs(tcph->win_size));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,  hTCPItem, 0);
//
//		strText = "校验和：";
//		strTmp.Format("0x%04hx", ntohs(tcph->chksum));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,  hTCPItem, 0);
//
//		strText = "紧急指针：";
//		strTmp.Format("%hu", ntohs(tcph->urg_ptr));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,  hTCPItem, 0);
//
//
//}
//
//
///* 解析DNS  offset为到dns首部的偏移量 */
//void decodeDNS(u_char *pkt_data, int offset, dns_header *dnsh, HTREEITEM parentNode)
//{
//		HTREEITEM hDNSItem;			//树形控件结点
//		CString strText, strTmp;
//
//		strText = "DNS （";
//		switch(dnsh->flags >> 15)
//		{
//		case 0:	strTmp = "Query）";		break;
//		case 1:	strTmp = "Response）";	break;
//		}
//		strText += strTmp;
//		hDNSItem = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//		strText = "标识：";
//		strTmp.Format("0x%04hx (%hu)", ntohs(dnsh->identifier), ntohs(dnsh->identifier)); 
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		strText = "标志：";
//		strTmp.Format("0x%04hx", ntohs(dnsh->flags));
//		strText += strTmp;
//
//		HTREEITEM hDNSFlag = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//		/* 标志子字段 */
//		strText = "QR：";
//		switch(ntohs(dnsh->flags) >> 15)
//		{
//		case 0: strTmp = "0 （查询报文）"	;	break;
//		case 1: strTmp = "1 （响应报文）";	break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "OpCode：";
//		switch((ntohs(dnsh->flags) >> 11) & 0x000f)
//		{
//		case 0: strTmp = "0 （标准查询）";	break;
//		case 1:	strTmp = "1 （反向查询）";	break;
//		case 2: strTmp = "2 （服务器状态请求）"; break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "AA：";
//		switch((ntohs(dnsh->flags) >> 10) & 0x0001)
//		{
//		case 0:	strTmp = "0 （非授权回答）"; break;
//		case 1: strText = "1 （授权回答）"; break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "TC：";
//		switch((ntohs(dnsh->flags) >> 9) & 0x0001)
//		{
//		case 0: strTmp = "0 （报文未截断）"; break;
//		case 1: strTmp = "1 （报文截断）";	break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "RD：";
//		switch((ntohs(dnsh->flags) >> 8) & 0x0001)
//		{
//		case 0: strTmp = "0"; break;
//		case 1: strTmp = "1 （希望进行递归查询）";	break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "RA：";
//		switch((ntohs(dnsh->flags) >> 7) & 0x0001)
//		{
//		case 0: strTmp = "0 （服务器不支持递归查询）"; break;
//		case 1: strTmp = "1 （服务器支持递归查询）";	break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "Reserved：";
//		strTmp.Format("%d", (ntohs(dnsh->flags) >> 4) & 0x0007);
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "rCode：";
//		switch(ntohs(dnsh->flags)  & 0x000f)
//		{
//		case 0: strTmp = "0 （无差错）";		break;
//		case 1: strTmp = "1 （格式差错）";	break;	
//		case 2: strTmp = "2 （DNS服务器问题）";	break;
//		case 3: strTmp = "3 （域名不存在或出错）";	break;
//		case 4: strTmp = "4 （查询类型不支持）";	break;
//		case 5: strTmp = "5 （在管理上禁止）";	break;
//		default: strTmp.Format("%d（保留）", ntohs(dnsh->flags) & 0x000f);				break;
//		}
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSFlag, 0);
//
//		strText = "查询记录数：";
//		strTmp.Format("%hu", ntohs(dnsh->questions));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		strText = "回答记录数：";
//		strTmp.Format("%hu", ntohs(dnsh->answers));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		strText = "授权回答记录数：";
//		strTmp.Format("%hu", ntohs(dnsh->authority));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		strText = "附加信息记录数：";
//		strTmp.Format("%hu", ntohs(dnsh->additional));
//		strText += strTmp;
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		strText = "查询部分：";
//		HTREEITEM hDNSQuery = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		/* 查询部分 */
//		char *p = (char*)(pkt_data + offset + 12);	
//
//		int query_num = 0, answer_num = 0, authority_num = 0, additional_num = 0;
//
//		if(ntohs(dnsh->questions) < 10)
//		{
//			while(query_num < ntohs(dnsh->questions))
//			{
//				char *name1 = (char*)malloc(strlen(p)+1);
//
//				translateName(name1, p);
//			
//				/* 跳过域名字段 */
//				while(*p)
//				{
//					++p;
//				}
//				++p;
//
//				strText.Format("%s", name1);
//				strText += "：";
//
//				dns_query *dnsq = (dns_query*)p;
//				u_short	type, classes;
//
//				type = ntohs(dnsq->type);
//				classes = ntohs(dnsq->classes);
//				
//				switch(type)
//				{
//				case 1:	strTmp = "type A"; break;
//				case 2:	strTmp = "type NS"; break;
//				case 5: strTmp = "type CNAME"; break;
//				case 6: strTmp = "type SOA"; break;
//				case 12: strTmp = "type PTR"; break;
//				case 15: strTmp = "type MX"; break;
//				case 28: strTmp = "type AAAA"; break;
//				case 255: strTmp = "type ANY"; break;
//				default: strTmp.Format("type UNKNOWN(%hu)", type); break;
//				}
//				strText += strTmp + ", ";
//
//				switch(classes)
//				{
//				case 1: strTmp = "class INTERNET"; break;
//				case 2: strTmp = "class CSNET";	break;
//				case 3: strTmp = "class COAS";	break;
//				default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
//				}
//				strText += strTmp;
//
//				g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSQuery, 0);
//
//				/* 跳过查询类型和查询类字段 */
//				p += sizeof(dns_query);
//
//				query_num++;
//				free(name1);
//			}
//		}
//
//		strText = "回答部分：";
//		HTREEITEM hDNSAnswer = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		/* 回答部分 */
//		while(answer_num < ntohs(dnsh->answers))
//		{
//
//			/* 指向指针 */
//			if(*(u_char*)p == 0xc0)
//			{
//				
//				/* 指向偏移量 		
//				++p;	
//				
//				char *name = (char*)(pkt_data + offset + *(u_char*)p);			// 域名
//				char *name1 = (char*)malloc(strlen(name)+1);
//
//			
//				translateName(name1, name);
//				
//				strText.Format("%s", name1);
//				strText += "：";
//
//  				free(name1);
//				*/
//					
//				char name[70];
//				char name1[70];
//
//				translateData(pkt_data, offset, name, p, 2);
//				translateName(name1, name);
//
//				strText.Format("%s", name1);
//				strText += "：";
//
//				/* 指向偏移量 */
//				++p;
//
//
//				/* 指向类型*/
//				++p;
//				dns_answer *dnsa = (dns_answer*)p;
//
//				u_short type =  ntohs(dnsa->type);
//				u_short classes = ntohs(dnsa->classes);
//				u_long  ttl  = ntohl(dnsa->ttl);
//
//				switch(type)
//				{
//				case 1:	strTmp = "type A"; break;
//				case 2:	strTmp = "type NS"; break;
//				case 5: strTmp = "type CNAME"; break;
//				case 6: strTmp = "type SOA"; break;
//				case 12: strTmp = "type PTR"; break;
//				case 15: strTmp = "type MX"; break;
//				case 28: strTmp = "type AAAA"; break;
//				case 255: strTmp = "type ANY"; break;
//				default: strTmp.Format("type UNKNOWN(%hu)", type); break;
//				}
//				strText += strTmp + ", ";
//
//				switch(classes)
//				{
//				case 1: strTmp = "class INTERNET"; break;
//				case 2: strTmp = "class CSNET";	break;
//				case 3: strTmp = "class COAS";	break;
//				default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
//				}
//				strText += strTmp + ", ";
//
//				strTmp.Format("ttl %lu", ttl);
//				strText += strTmp + ", ";
//
//				/* 指向资源数据长度 */
//				p += sizeof(dns_answer);
//				
//				u_short data_len = ntohs(*(u_short*)p);
//
//				strTmp.Format("len %hu", data_len);
//				strText += strTmp + ", ";
//
//				/* 指向资源数据 */
//				p += sizeof(u_short);
//
//				/* 查询类型为NS、CNAME、PTR的资源数据 */
//				if(type == 2 || type == 5 || type == 12)
//				{
//	
//					/* 资源数据为指针0xc0 + 偏移量*/
//					if(*(u_char*)p == 0xc0)
//					{				
//						/* 根据偏移量获取数据 											
//						char *data = (char*)(pkt_data + offset + *(u_char*)(p+1));			// 域名
//						char *data1 = (char*)malloc(strlen(data)+1);
//
//						translateName(data1, data);
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//
//						free(data1);
//						*/
//						char data[70];
//						char data1[70];
//
//						translateData(pkt_data, offset, data, p, 2);
//						translateName(data1, data);
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//
//					}
//					/* 资源数据存在指针0xc0 + 偏移量 */
//					else if(isNamePtr(p))
//					{
//						char data[70];
//						char data1[70];
//
//						translateData(pkt_data, offset, data, p, data_len);		// 去掉指针0xc0+偏移量
//						translateName(data1, data);								// 去掉'.'
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//					}
//					/* 资源数据中不存在指针0xc0 + 偏移量 */
//					else
//					{
//						char *data = (char*)malloc(data_len);
//
//						translateName(data, p);
//
//						strTmp.Format("%s", data);
//						strText += strTmp;
//						free(data);
//						
//					}
//				}
//				/* 查询类型为A的资源数据 */
//				else if(type == 1)
//				{
//					ip_address data = *(ip_address*)p;
//
//					strTmp.Format("%d.%d.%d.%d", data.byte1, data.byte2, data.byte3, data.byte4);
//					strText += strTmp;
//				}
//
//				g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSAnswer, 0);
//			
//				/* 跳过数据部分 */
//				p += data_len;
//
//		
//
//			}//if
//			answer_num++;
//		}
//
//		strText = "授权回答部分：";
//		HTREEITEM hDNSAuthority = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		/* 授权回答部分 */
//		while(authority_num < ntohs(dnsh->authority))
//		{
//
//			/* 指向指针 */
//			if(*(u_char*)p == 0xc0)
//			{
//				
//				/* 指向偏移量 		
//				++p;	
//				
//				char *name = (char*)(pkt_data + offset + *(u_char*)p);			// 域名
//				char *name1 = (char*)malloc(strlen(name)+1);
//				translateName(name1, name);
//				
//				strText.Format("%s", name1);
//				strText += "：";
//
//				free(name1);
//				*/
//				char name[70];
//				char name1[70];
//
//				translateData(pkt_data, offset, name, p, 2);
//				translateName(name1, name);
//
//				strText.Format("%s", name1);
//				strText += "：";
//
//				/* 指向偏移量 */
//				++p;
//
//				/* 指向类型*/
//				++p;
//				dns_answer *dnsa = (dns_answer*)p;
//
//				u_short type =  ntohs(dnsa->type);
//				u_short classes = ntohs(dnsa->classes);
//				u_long  ttl  = ntohl(dnsa->ttl);
//
//				switch(type)
//				{
//				case 1:	strTmp = "type A"; break;
//				case 2:	strTmp = "type NS"; break;
//				case 5: strTmp = "type CNAME"; break;
//				case 6: strTmp = "type SOA"; break;
//				case 12: strTmp = "type PTR"; break;
//				case 15: strTmp = "type MX"; break;
//				case 28: strTmp = "type AAAA"; break;
//				case 255: strTmp = "type ANY"; break;
//				default: strTmp.Format("type UNKNOWN(%hu)", type); break;
//				}
//				strText += strTmp + ", ";
//
//				switch(classes)
//				{
//				case 1: strTmp = "class INTERNET"; break;
//				case 2: strTmp = "class CSNET";	break;
//				case 3: strTmp = "class COAS";	break;
//				default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
//				}
//				strText += strTmp + ", ";
//
//				strTmp.Format("ttl %lu", ttl);
//				strText += strTmp + ", ";
//
//				/* 指向资源数据长度 */
//				p += sizeof(dns_answer);
//				
//				u_short data_len = ntohs(*(u_short*)p);
//
//				strTmp.Format("len %hu", data_len);
//				strText += strTmp + ", ";
//
//				/* 指向资源数据 */
//				p += sizeof(u_short);
//
//				/* 查询类型为NS、CNAME、PTR的资源数据 */
//				if(type == 2 || type == 5 || type == 12)
//				{
//	
//					/* 资源数据为指针0xc0 + 偏移量*/
//					if(*(u_char*)p == 0xc0)
//					{				
//						/* 根据偏移量获取数据 											
//						char *data = (char*)(pkt_data + offset + *(u_char*)(p+1));			// 域名
//						char *data1 = (char*)malloc(strlen(data)+1);
//
//						translateName(data1, data);
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//
//						free(data1);
//						*/
//
//						char data[70];
//						char data1[70];
//
//						translateData(pkt_data, offset, data, p, 2);
//						translateName(data1, data);
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//					}
//					/* 资源数据存在指针0xc0 + 偏移量 */
//					else if(isNamePtr(p))
//					{
//						char data[70];
//						char data1[70];
//
//						translateData(pkt_data, offset, data, p, data_len);		// 去掉指针0xc0+偏移量
//						translateName(data1, data);								// 去掉'.'
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//					}
//					/* 资源数据中不存在指针0xc0 + 偏移量 */
//					else
//					{
//						char *data = (char*)malloc(data_len);
//
//						translateName(data, p);
//
//						strTmp.Format("%s", data);
//						strText += strTmp;
//						free(data);
//						
//					}
//				}
//				/* 查询类型为A的资源数据 */
//				else if(type == 1)
//				{
//					ip_address data = *(ip_address*)p;
//
//					strTmp.Format("%d.%d.%d.%d", data.byte1, data.byte2, data.byte3, data.byte4);
//					strText += strTmp;
//				}
//
//				g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSAuthority, 0);
//			
//				/* 跳过数据部分 */
//				p += data_len;
//
//
//			}//if
//			authority_num++;
//		}
//
//		strText = "附加信息部分：";
//		HTREEITEM hDNSAdditional = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSItem, 0);
//
//		/* 附加信息部分 */
//		while(additional_num < ntohs(dnsh->additional))
//		{
//
//			/* 指向指针 */
//			if(*(u_char*)p == 0xc0)
//			{
//				
//				/* 指向偏移量 		
//				++p;	
//				
//				char *name = (char*)(pkt_data + offset + *(u_char*)p);			// 域名
//				char *name1 = (char*)malloc(strlen(name)+1);
//
//				translateName(name1, name);
//				
//				strText.Format("%s", name1);
//				strText += "：";
//
//				free(name1);
//				*/
//				char name[70];
//				char name1[70];
//
//				translateData(pkt_data, offset, name, p, 2);
//				translateName(name1, name);
//
//				strText.Format("%s", name1);
//				strText += "：";
//
//				/* 指向偏移量 */
//				++p;
//
//				/* 指向类型*/
//				++p;
//				dns_answer *dnsa = (dns_answer*)p;
//
//				u_short type =  ntohs(dnsa->type);
//				u_short classes = ntohs(dnsa->classes);
//				u_long  ttl  = ntohl(dnsa->ttl);
//
//				switch(type)
//				{
//				case 1:	strTmp = "type A"; break;
//				case 2:	strTmp = "type NS"; break;
//				case 5: strTmp = "type CNAME"; break;
//				case 6: strTmp = "type SOA"; break;
//				case 12: strTmp = "type PTR"; break;
//				case 15: strTmp = "type MX"; break;
//				case 28: strTmp = "type AAAA"; break;
//				case 255: strTmp = "type ANY"; break;
//				default: strTmp.Format("type UNKNOWN(%hu)", type); break;
//				}
//				strText += strTmp + ", ";
//
//				switch(classes)
//				{
//				case 1: strTmp = "class INTERNET"; break;
//				case 2: strTmp = "class CSNET";	break;
//				case 3: strTmp = "class COAS";	break;
//				default: strTmp.Format("class UNKNOWN(%hu)", classes); break;
//				}
//				strText += strTmp + ", ";
//
//				strTmp.Format("ttl %lu", ttl);
//				strText += strTmp + ", ";
//
//				/* 指向资源数据长度 */
//				p += sizeof(dns_answer);
//				
//				u_short data_len = ntohs(*(u_short*)p);
//
//				strTmp.Format("len %hu", data_len);
//				strText += strTmp + ", ";
//
//				/* 指向资源数据 */
//				p += sizeof(u_short);
//
//				/* 查询类型为NS、CNAME、PTR的资源数据 */
//				if(type == 2 || type == 5 || type == 12)
//				{
//	
//					/* 资源数据为指针0xc0 + 偏移量*/
//					if(*(u_char*)p == 0xc0)
//					{				
//						/* 根据偏移量获取数据 											
//						char *data = (char*)(pkt_data + offset + *(u_char*)(p+1));			// 域名
//						char *data1 = (char*)malloc(strlen(data)+1);
//
//						translateName(data1, data);
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//
//						free(data1);
//						*/
//
//						char data[70];
//						char data1[70];
//
//						translateData(pkt_data, offset, data, p, 2);
//						translateName(data1, data);
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//					}
//					/* 资源数据存在指针0xc0 + 偏移量 */
//					else if(isNamePtr(p))
//					{
//						char data[70];
//						char data1[70];
//
//						translateData(pkt_data, offset, data, p, data_len);		// 去掉指针0xc0+偏移量
//						translateName(data1, data);								// 去掉'.'
//
//						strTmp.Format("%s", data1);
//						strText += strTmp;
//					}
//					/* 资源数据中不存在指针0xc0 + 偏移量 */
//					else
//					{
//						char *data = (char*)malloc(data_len);
//
//						translateName(data, p);
//
//						strTmp.Format("%s", data);
//						strText += strTmp;
//						free(data);
//						
//					}
//				}
//				/* 查询类型为A的资源数据 */
//				else if(type == 1)
//				{
//					ip_address data = *(ip_address*)p;
//
//					strTmp.Format("%d.%d.%d.%d", data.byte1, data.byte2, data.byte3, data.byte4);
//					strText += strTmp;
//				}
//
//				g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDNSAdditional, 0);
//			
//				/* 跳过数据部分 */
//				p += data_len;
//
//			}//if
//			additional_num++;
//		}		
//}
//
///* 解析HTTP offset为到HTTP报文的偏移量*/
//void decodeHTTP(u_char *pkt_data, int offset, HTREEITEM parentNode)
//{
//	u_char *p = (pkt_data + offset);
//	ip_header *iph = (ip_header*)(pkt_data + 14);
//	tcp_header *tcph = (tcp_header*)(pkt_data + 14 + (iph->ver_hrdlen & 0x0f) *4);
//
//	int http_len = ntohs(iph->totallen) - (iph->ver_hrdlen & 0x0f) * 4 - (ntohs(tcph->hdrlen_rsv_flags) >> 12)*4;
//	int count = 0;
//
//	CString strText;
//	
//	strText = "HTTP";
//	HTREEITEM hHTTPItem = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//	
//	while( count < http_len)
//	{
//		strText = "";
//		while(*p != '\r')
//		{
//			strText += *p;
//			++p;
//			++count;
//		}
//		strText += "\\r\\n";
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hHTTPItem, 0);
//
//		p += 2;
//		count += 2;
//	}	
//}
//
//
///* 解析DHCP offset为到DHCP报文的偏移量*/
//void decodeDHCP(u_char *pkt_data, int offset, HTREEITEM parentNode)
//{
//	dhcp_header *dhcph = (dhcp_header*)(pkt_data + offset);
//	u_char *p = (u_char*)(pkt_data + offset + sizeof(dhcp_header));	//p指向客户机硬件地址
//
//	CString strText, strTmp;
//
//	strText = "DHCP";
//	HTREEITEM hDHCPItem = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, parentNode, 0);
//
//	/* 解析dhcp首部 */
//	strText = "报文类型：";
//	strTmp.Format("%d", dhcph->op);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//	strText = "硬件类型：";
//	strTmp.Format("%d", dhcph->htype);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//	strText = "硬件地址长度：";
//	strTmp.Format("%d", dhcph->hlen);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//	strText = "跳数：";
//	strTmp.Format("%d", dhcph->hops);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//	strText = "事务ID：";
//	strTmp.Format("0x%08lx", ntohl(dhcph->xid));
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	strText = "客户启动时间：";
//	strTmp.Format("%hu", ntohs(dhcph->secs));
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	strText = "标志：";
//	strTmp.Format("0x%04hx", ntohs(dhcph->flags));
//	strText += strTmp;
//	switch(ntohs(dhcph->flags) >> 15)
//	{
//	case 0: strText += "（广播）"; break;
//	case 1: strText += "（单播）"; break;
//	}
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	strText = "客户机IP地址：";
//	strTmp.Format("%d.%d.%d.%d", dhcph->ciaddr.byte1, dhcph->ciaddr.byte2, dhcph->ciaddr.byte3, dhcph->ciaddr.byte4);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	strText = "你的（客户）IP地址：";
//	strTmp.Format("%d.%d.%d.%d", dhcph->yiaddr.byte1, dhcph->yiaddr.byte2, dhcph->yiaddr.byte3, dhcph->yiaddr.byte4);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	strText = "服务器IP地址：";
//	strTmp.Format("%d.%d.%d.%d", dhcph->siaddr.byte1, dhcph->siaddr.byte2, dhcph->siaddr.byte3, dhcph->siaddr.byte4);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	strText = "网关IP地址：";
//	strTmp.Format("%d.%d.%d.%d", dhcph->giaddr.byte1, dhcph->giaddr.byte2, dhcph->giaddr.byte3, dhcph->giaddr.byte4);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	/*  解析dhcp首部剩余部分 */
//	mac_address *chaddr = (mac_address*)p; 
//						
//	strText = "客户机mac地址：";
////	strTmp.Format("%02x-%02x-%02x-%02x-%02x-%02x", chaddr->byte1, chaddr->byte2, chaddr->byte3, chaddr->byte4, chaddr->byte5, chaddr->byte6);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	// 跳过客户机硬件地址
//	p += 16;		
//
//	strText = "服务器主机名：";
//	strTmp.Format("%s", p);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0,hDHCPItem, 0);
//
//	// 跳过服务器主机名
//	p += 64;		
//
//	strText = "引导文件名：";
//	strTmp.Format("%s", p);
//	strText += strTmp;
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//	// 跳过引导文件名
//	p += 128;
//
//	if(ntohl(*(u_long*)p) == 0x63825363)
//	{
//		strText = "Magic cookie: DHCP";
//		g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//	}
//
//	// 跳过magic cookie
//	p += 4;
//
//	while(*p != 0xff)
//	{
//		switch(*p)
//		{
//		case 53: 
//			{	strText = "选项：（53）DHCP报文类型";
//				 switch(*(p+2))
//				 {
//					case 1: strText += "（Discover）"; break;
//					case 2: strText += "（Offer）"; break;
//					case 3: strText += "（Request）"; break;
//					case 4: strText += "（Decline）"; break;
//					case 5: strText += "（ACK）"; break;
//					case 6: strText += "（NAK）"; break;
//					case 7: strText += "（Release）"; break;
//					case 8: strText += "（Inform）"; break;
//				 }
//				 HTREEITEM hDHCPOption;
//				 hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 strText = "长度：";
//				 strTmp.Format("%d", *(++p));
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 strText = "DHCP：";
//				 strTmp.Format("%d", *(++p));
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);
//				 
//				 // 指向下一个选项
//				 ++p;
//			}
//			break;
//
//		case 50: 
//			{	
//				strText = "选项：（50）请求IP地址";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 strText = "长度：";
//				 strTmp.Format("%d", *(++p));
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 ip_address *addr = (ip_address*)(++p);
//				 strText = "地址：";
//				 strTmp.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//				 
//				 // 指向下一个选项
//				 p += 4;
//			}
//				 break;
//
//		case 51:
//			{
//				strText = "选项：（51）IP地址租约时间";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);	
//
//				 strText = "长度：";
//				 strTmp.Format("%d", *(++p));
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 u_int time = *(++p);
//				 strText = "租约时间：";
//				 strTmp.Format("%u", time);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 // 指向下一个选项
//				 p += 4;
//			}
//				 break;
//
//		case 61: 
//			{
//				 strText = "选项：（61）客户机标识";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 strText = "硬件类型：";
//				 if(*(++p) == 0x01)
//				 {
//					strTmp = "以太网（0x01）";		
//					strText += strTmp;
//					g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//					mac_address *addr = (mac_address*)(++p);
//					strText = "客户机标识：";
////					strTmp.Format("%02x-%02x-%02x-%02x-%02x-%02x", addr->byte1, addr->byte2, addr->byte3, addr->byte4, addr->byte5, addr->byte6);
//					strText += strTmp;
//					g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//					p += 6;
//				 }
//				 else
//				 {
//					strTmp.Format("%d", *p);
//					strText += strTmp;
//					g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//					p += len;
//
//				 }	
//			}
//				 break;
//
//		case 60: 
//			{
//				 strText = "选项：（60）供应商类标识";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 int count = 0;
//				 strText = "供应商类标识：";
//
//				 for(;count < len; count++)
//				 {
//					 strTmp.Format("%c", *(++p));
//					 strText += strTmp;
//				 }
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	 
//
//				 ++p;
//			}
//				 break;
//
//		case 54: 
//			{	
//				 strText = "选项：（54）服务器标识";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 ip_address *addr = (ip_address*)(++p);
//				 strText = "服务器标识：";
//				 strTmp.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 p += 4;
//			}
//				 break;
//
//		case 1:	 
//			{
//				 strText = "选项：（1）子网掩码";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 ip_address *submask = (ip_address*)(++p);
//				 strText = "子网掩码：";
////				 strTmp.Format("%d.%d.%d.%d", submask->byte1, submask->byte2, submask->byte3, submask->byte4);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 p += 4;
//			}
//				 break;
//
//		case 3:  
//			{
//				 strText = "选项：（3）路由器";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//				 int count = 0;
//				 while( count < len)
//				 {
//					 ip_address *addr = (ip_address*)(++p);
//					 strText = "路由器：";
//					 strTmp.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
//					 strText += strTmp;
//					 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//					 count += 4;
//					 p += 4;
//				 }
//			}
//				 break;
//
//		case 6:  
//			{
//				 strText = "选项：（6）DNS服务器";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	 
//
//				 int count = 0;
//				 ++p;
//				 while( count < len)
//				 {
//					 ip_address *addr = (ip_address*)p;
//					 strText = "DNS服务器：";
//					 strTmp.Format("%d.%d.%d.%d", addr->byte1, addr->byte2, addr->byte3, addr->byte4);
//					 strText += strTmp;
//					 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	
//
//					 count += 4;
//					 p += 4;
//				 }
//			}
//				 break;
//
//
//		case 12: 
//			{	
//				 strText = "选项：（12）主机名";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	 
//
//				 int count = 0;
//				 strText = "主机名：";
//
//				 for(;count < len; count++)
//				 {
//					 strTmp.Format("%c", *(++p));
//					 strText += strTmp;
//				 }
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	 
//
//				 ++p;
//			}
//				 break;
//
//		case 0: ++p;
//				break;
//
//		default: strText = "选项：（";
//				 strTmp.Format("%d", *p);
//				 strText += strTmp + "）";
//				 HTREEITEM hDHCPOption = g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);
//
//				 int len = *(++p);
//				 strText = "长度：";
//				 strTmp.Format("%d", len);
//				 strText += strTmp;
//				 g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPOption, 0);	 
//
//				 // 指向选项内容
//				 ++p;
//
//				 // 跳过选项内容
//				 p += len;
//				 break;
//		}
//
//	}
//	strText = "选项：（255）结束";
//	g_pTreeCtrlPacketInfo->InsertItem(strText, 0, 0, hDHCPItem, 0);	 
//	
//
//
//}
//
///* 判断data中有无指针0xc0,并返回指针在data中的位置*/
//int isNamePtr(char *data)
//{
//	char *p = data;
//	int pos = 0;
//
//	while(*p)
//	{
//		if(*(u_char*)p == 0xc0)
//		{
//			return pos;
//		}
//		++p;
//		++pos;
//	}
//
//	return 0;
//}
//void translateName(char *name1, const char *name2)
//{
//	strcpy(name1, name2);
//
//	char *p = name1;
//	bool canMove = false;
//
//	if( !isalnum(*(u_char*)p) && *(u_char*)p !=  '-')
//	{
//		canMove = true;
//	}
//
//	/* 将计数转换为'.' */
//	while(*p)
//	{
//		if(!isalnum(*(u_char*)p) && *(u_char*)p != '-')
//			*p = '.';
//
//		++p;
//	}
//
//
//	/* 将域名整体向前移1位 */
//	if(canMove)
//	{
//		p = name1;
//		while(*p)
//		{
//			*p = *(p+1);
//			++p;
//		}
//	}
//
//	
//}
//
///* DNS资源记录数据部分转换 将带有指针0xc0的data2转换为不带指针的data1 offset为到dns首部的偏移量*/
//void translateData(u_char *pkt_data, int offset, char *data1, char *data2, int data2_len)
//{
//	char *p = data2;
//	int count = 0, i = 0;
//
//	/* 遍历data2 */
//	while(count < data2_len )
//	{			
//		/* 指针 */
//		if(*(u_char*)p == 0xc0)
//		{
//			++p;
//
//			/* 读取指针所指向的数据 */
//			char *data_ptr = (char*)(pkt_data + offset + *(u_char*)p);
//
//			int pos;
//			pos = isNamePtr(data_ptr);
//			if(pos)
//			{
//				translateData(pkt_data, offset, data1+i, data_ptr, pos+2);
//			}
//			else
//			{
//				strcpy(data1+i, data_ptr);
//				i += strlen(data_ptr)+1;
//			}
//			count += 2;
//		}
//		else 
//		{
//			data1[i++] = *p;
//			++p;
//			++count;
//		}
//
//	}
//}
//
//
//
//
///* 点击列表事件 */
//void CSnifferUIDlg::OnClickList1(NMHDR* pNMHDR, LRESULT* pResult) 
//{
//	// TODO: Add your control notification handler code here
//	
//	HTREEITEM hIDItem;		//树形控件结点
//
//	int sel_row;
//	u_short *eth_type;
//	mac_address *saddr, *daddr;
//	arp_header	*arph;
//	ip_header	*iph;
//	icmp_header *icmph;
//	udp_header	*udph;
//	tcp_header	*tcph;
//	dns_header	*dnsh;
//
//	CString strText,strTmp;
//	
//
//	/* 删除所有结点 */
//	m_tree.DeleteAllItems();
//
//	/* 获取选中行的行号 */
//	sel_row = pList1->GetSelectionMark();
//
//	/* 获取选中行的报文信息 */
//	POSITION pos = linklist.FindIndex(sel_row);
//	packet_header *ppkth = &linklist.GetAt(pos);
//	if(ppkth == NULL)
//	{
//		AfxMessageBox("ppkth为空指针", MB_OK);
//		return;
//	}
//
//	saddr = &ppkth->saddr;
//	daddr = &ppkth->daddr;
//	eth_type = &ppkth->eth_type;
//	arph = ppkth->arph;
//	iph = ppkth->iph;
//	icmph = ppkth->icmph;
//	udph = ppkth->udph;
//	tcph = ppkth->tcph;
//	dnsh = ppkth->dnsh;
//
//	/* 打印数据包到编辑框 */
//	int count = 0;
//	u_char *p = ppkth->pkt_data;
//	while(count < ppkth->caplen)
//	{
//		strTmp.Format("%02hx ", *p);
//		strText += strTmp;
//
//		++p;
//		++count;
//	}	
//	GetDlgItem(IDC_EDIT1)->SetWindowText(strText);
//
//
//	/* 建立编号结点 */
//	strText.Format("第%d个数据包", sel_row + 1);
//	hIDItem = m_tree.InsertItem(strText);
//
//	/* 建立以太网帧结点 */
//	decodeFrame(saddr, daddr, eth_type, &hIDItem);
//	
//	/* 建立ip结点 */
//	if(iph != NULL)
//	{
//		decodeIP(iph, &hIDItem);		
//	}
//	
//	/* 建立arp结点 */
//	if(arph != NULL)
//	{
//		decodeARP(arph, &hIDItem);
//	}
//
//	/* 建立icmp结点 */
//	if(icmph != NULL)
//	{
//		decodeICMP(icmph, &hIDItem);
//	}
//															
//	/* 建立udp结点 */
//	if(udph != NULL)
//	{
//		decodeUDP(udph, &hIDItem);	
//	}
//
//	/* 建立tcp结点 */
//	if(tcph != NULL)
//	{
//		decodeTCP(tcph, &hIDItem);
//	}
//
//	/* 建立dns结点 */
//	if(dnsh != NULL)
//	{
//		int offset;
//
//		switch(iph->proto)
//		{
//		case 6:	 offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + (ntohs(tcph->hdrlen_rsv_flags) >> 12)*4;	break;	//tcph
//		case 17: offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + 8 ;	break;											//udph 
//			
//		}
//		 
//															
//		decodeDNS(ppkth->pkt_data, offset, dnsh, &hIDItem);	
//	}
//
//	/* 建立http结点 */
//	if(tcph != NULL && (ntohs(tcph->srcport) == 80 || ntohs(tcph->dstport) == 80))
//	{
//		int offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + (ntohs(tcph->hdrlen_rsv_flags) >> 12)*4;
//
//		decodeHTTP(ppkth->pkt_data, offset,&hIDItem);
//	}
//
//	/* 建立dhcp结点 */
//	if(udph != NULL && ( (ntohs(udph->srcport) == 67 && ntohs(udph->dstport) == 68) || (ntohs(udph->srcport) == 68 && ntohs(udph->dstport) == 67) ))
//	{
//		int offset = 14 + (iph->ver_hrdlen & 0x0f)*4 + 8;
//
//		decodeDHCP(ppkth->pkt_data, offset, &hIDItem);
//	}
//	*pResult = 0;
//}


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
