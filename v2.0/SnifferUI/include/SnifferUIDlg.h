// SnifferUIDlg.h : header file
//

#include "afxwin.h"
#if !defined(AFX_SNIFFERUIDLG_H__22E6FA67_26EB_4787_8108_560D03B16680__INCLUDED_)
#define AFX_SNIFFERUIDLG_H__22E6FA67_26EB_4787_8108_560D03B16680__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIDlg dialog

class CSnifferUIDlg : public CDialog
{
// Construction
public:
	CSnifferUIDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CSnifferUIDlg)
	enum { IDD = IDD_SNIFFERUI_DIALOG };
	CButton			btnStart_;
	CButton			btnPause_;
	CButton			btnStop_;
	CButton			btnFilter_;
	CButton			btnClear_;
	CComboBox		comboBoxDevlist_;
	CListCtrl		listCtrlPacketList_;
	CTreeCtrl		treeCtrlPacketInfo_;
	CEdit			editCtrlPacketData_;
	//CRichEditCtrl	richEditCtrlFilterInput_;
	CComboBox		comboBoxFilterInput_;

	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSnifferUIDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	CMenu		m_Menu;
	HICON		m_hIcon;
	CWinThread *myWinThread;
	int			m_nSelectedItemIndex;			// ListCtrl的选中行下标
	CFont		m_font;							// ListCtrl的字体
	bool		m_isCapturing;					// 正在抓包的标志
	// Generated message map functions
	//{{AFX_MSG(CSnifferUIDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClickedStart();
	afx_msg void OnClickedPause();
	afx_msg void OnClickedStop();
	afx_msg void OnClickedFilter();
	afx_msg void OnClickedClear();
	afx_msg void OnClickedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnKeydownList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnClickedMenuFileExit();
	afx_msg void OnClickedMenuHelpAbout();
	afx_msg void OnClickedMenuFileSaveAs();
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SNIFFERUIDLG_H__22E6FA67_26EB_4787_8108_560D03B16680__INCLUDED_)
