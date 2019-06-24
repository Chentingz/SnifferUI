// ShortCutDialog.cpp : 实现文件
//

#include "stdafx.h"
#include "SnifferUI.h"
#include "ShortCutDialog.h"
#include "afxdialogex.h"


// CShortCutDialog 对话框

IMPLEMENT_DYNAMIC(CShortCutDialog, CDialog)

CShortCutDialog::CShortCutDialog(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_SHORTCUT_DIALOG, pParent)
{

}

CShortCutDialog::~CShortCutDialog()
{
}

void CShortCutDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_listCtrlShortCut);
}

void CShortCutDialog::initialListCtrl()
{
	DWORD dwStyle = m_listCtrlShortCut.GetExtendedStyle();	// 添加列表控件的网格线
	dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES;
	m_listCtrlShortCut.SetExtendedStyle(dwStyle);
	m_listCtrlShortCut.GetHeaderCtrl()->EnableWindow(false);// 禁止列拉伸

	CRect rect;
	m_listCtrlShortCut.GetWindowRect(&rect);
	ScreenToClient(&rect);

	/* 添加表头 */
	int index = 0;
	m_listCtrlShortCut.InsertColumn(++index, "快捷键", LVCFMT_CENTER, rect.Width() * 0.5);
	m_listCtrlShortCut.InsertColumn(++index, "功能", LVCFMT_CENTER, rect.Width() * 0.5);

	UINT mask = LVIF_PARAM | LVIF_TEXT;
	int row = 0;
	int col = 0;
		
	/* 添加一行 */	
	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + G", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, ++col, "获得数据包列表选中项焦点");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + O", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "打开文件");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + W", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "关闭文件");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + S", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "另存为");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Alt + F4", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "退出");
}


BEGIN_MESSAGE_MAP(CShortCutDialog, CDialog)
END_MESSAGE_MAP()


// CShortCutDialog 消息处理程序


BOOL CShortCutDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  在此添加额外的初始化
	initialListCtrl();

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
