#pragma once

#include <QThread>

#include "Public.h"
#include "pcap.h"

class PcapThread : public QThread
{
	Q_OBJECT
public:
	PcapThread();
    PcapThread(pcap_t *handle, ushort port);
	virtual ~PcapThread();

	void run();

    void Loop(const struct pcap_pkthdr *header, const uchar *pkt_data);

	double getTimeDifference(long,long);

signals:
	void signal_PayloadData(_MessageContent MsgCon, QByteArray payload);

private:
	pcap_t *m_pDev;
    ushort p_Port;

    _MessageContent TCP(const sniff_ip *ip, int size_ip, uint len, const uchar *buffer, QByteArray &payload);
	_MessageContent UDP(const sniff_ip *ip, int size_ip, const uchar *buffer, QByteArray &payload);


	//��16�ֽ�Ϊ��λ��ӡ���ݣ�ƫ��ʮ������ascii
    void print_hex_ascii_line(const uchar *payload, int len, int offset);

	/*
	*��ӡ����Ч�غ����ݣ������ӡ���������ݣ�
	*/
    void print_payload(const uchar *payload, int len);
	
};

