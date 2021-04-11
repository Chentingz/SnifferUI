// SnifferUI.h : main header file for the SNIFFERUI application
//

#if !defined(AFX_SNIFFERUI_H__F6F0F8D9_180D_4884_AE2B_3F3EF81EC4A8__INCLUDED_)
#define AFX_SNIFFERUI_H__F6F0F8D9_180D_4884_AE2B_3F3EF81EC4A8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIApp:
// See SnifferUI.cpp for the implementation of this class
//

class CSnifferUIApp : public CWinApp
{
public:
	CSnifferUIApp();
// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSnifferUIApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CSnifferUIApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SNIFFERUI_H__F6F0F8D9_180D_4884_AE2B_3F3EF81EC4A8__INCLUDED_)
