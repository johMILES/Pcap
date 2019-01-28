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

    void Loop(const struct pcap_pkthdr *header, const unsigned char *pkt_data);

	double getTimeDifference(long,long);

signals:
	void signal_PayloadData(_MessageContent MsgCon, QByteArray payload);

private:
	pcap_t *m_pDev;
    unsigned short p_Port;

    _MessageContent TCP(const sniff_ip *ip, int size_ip, uint len, const uchar *buffer, QByteArray &payload);
	_MessageContent UDP(const sniff_ip *ip, int size_ip, const uchar *buffer, QByteArray &payload);


	//以16字节为单位打印数据：偏移十六进制ascii
    void print_hex_ascii_line(const uchar *payload, int len, int offset);

    void print_payload(const unsigned char *payload, int len);
	
};

