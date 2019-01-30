#pragma once

#ifndef PCAPTHREAD_H
#define PCAPTHREAD_H

#include <QThread>

#include "Public.h"
#include "pcap.h"


class PcapThread : public QThread
{
//	Q_OBJECT
public:
    PcapThread(pcap_t *handle, unsigned short port, QObject *object = 0);
	virtual ~PcapThread();

    void run();

    //解析数据包
    void parsingDataPackets(const struct pcap_pkthdr *header, const unsigned char *pkt_data);

    //计算当前数据包间隔时间
    double getTimeDifference(long timesec,long timeusec);


private:
    pcap_t *m_pDev;
    unsigned short p_Port;

    void TCP(MessageContent &MsgCon, int iPLength, unsigned int len, const unsigned char *pkt_data);
    void UDP(MessageContent &MsgCon, int iPLength, const unsigned char *pkt_data);

    //以16字节为单位打印数据：偏移十六进制ascii
    void print_hex_ascii_line(const unsigned char *payload, int len, int offset);

    //打印包有效载荷数据（避免打印二进制数据）
    void print_payload(const unsigned char *payload, int len);
	
};



#endif // PCAPTHREAD_H
