#pragma once
/* 
*	该类用于捕获数据包另存为转储文件
*   本质是对默认保存的转储文件拷贝到指定位置 
*/
class PacketDumper
{
private:
	CString		m_path;			// 转储文件默认存储路径

public:
	PacketDumper();
	~PacketDumper();

	void setPath(CString path);
	CString getPath();

	void dump(CString path);
	void copyFile(CFile *dest, CFile *src);
};

