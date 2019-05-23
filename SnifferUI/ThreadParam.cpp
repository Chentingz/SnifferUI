#include "stdafx.h"
#include "ThreadParam.h"

ThreadParam::ThreadParam()
{
	m_adhandle = NULL;
	m_pool = NULL;
}

ThreadParam::ThreadParam(pcap_t *adhandle, PacketPool *pool , pcap_dumper_t *dumper, int mode)
{
	m_adhandle = adhandle;
	m_pool = pool;
	m_dumper = dumper;
	m_mode = mode;
}

ThreadParam::~ThreadParam()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}
