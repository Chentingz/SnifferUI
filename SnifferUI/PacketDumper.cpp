#include "stdafx.h"
#include "PacketDumper.h"


PacketDumper::PacketDumper()
{
}

PacketDumper::~PacketDumper()
{
}

void PacketDumper::setPath(CString path)
{
	m_path = path;
}

CString PacketDumper::getPath()
{
	return m_path;
}

//CString PacketDumper::getFileName()
//{
//	return m_path.Sub;
//}

/**
*	@brief	将m_path路径上的默认转储文件另存到path路径上
*	@param	path 另存为路径
*	@return	-
*/
void PacketDumper::dump(CString path)
{
	CFile dumpFile(m_path, CFile::modeRead | CFile::shareDenyNone);
	CFile saveAsFile(path, CFile::modeCreate | CFile::modeWrite);
	
	copyFile(&saveAsFile, &dumpFile);
	
	saveAsFile.Close();
	dumpFile.Close();
}

/**
*	@brief	将src文件的内容拷贝到dest文件
*	@param	dest 目标文件	src 源文件
*	@return	-
*/
void PacketDumper::copyFile(CFile * dest, CFile * src)
{
	char buf[1024];
	int  byteCount;

	while ((byteCount = src->Read(buf, sizeof(buf))) > 0)
		dest->Write(buf, byteCount);
}
