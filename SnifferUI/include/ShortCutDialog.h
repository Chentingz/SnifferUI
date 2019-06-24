#pragma once
#include "afxcmn.h"


// CShortCutDialog 对话框

class CShortCutDialog : public CDialog
{
	DECLARE_DYNAMIC(CShortCutDialog)

public:
	CShortCutDialog(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CShortCutDialog();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SHORTCUT_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listCtrlShortCut;
	void initialListCtrl();
	virtual BOOL OnInitDialog();
};
