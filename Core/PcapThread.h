#pragma once

#include <QThread>

#include "Public.h"
#include "pcap.h"

class PcapThread : public QThread
{
	Q_OBJECT
public:
	PcapThread();
    PcapThread(pcap_t *handle, unsigned short port);
	virtual ~PcapThread();

	void run();

    void Loop(const struct pcap_pkthdr *header, const unsigned char *pkt_data);

	double getTimeDifference(long,long);

signals:
	void signal_Data(_MessageContent MsgCon, QByteArray payload);

private:
	pcap_t *m_pDev;
    unsigned short p_Port;

    _MessageContent TCP(const sniff_ip *ip, int size_ip, unsigned int len, const unsigned char *buffer, QByteArray &payload);
    void UDP(const unsigned char *buffer);


	//以16字节为单位打印数据：偏移十六进制ascii
    void print_hex_ascii_line(const unsigned char *payload, int len, int offset);

	/*
	*打印包有效载荷数据（避免打印二进制数据）
	*/
    void print_payload(const unsigned char *payload, int len);
	
};

