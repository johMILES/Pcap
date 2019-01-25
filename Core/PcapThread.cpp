#include "PcapThread.h"

#include <QDebug>
#include <QLatin1String>
#include <QByteArray>
#include <QString>

PcapThread *p_PcapThread = NULL;
PcapThread::PcapThread()
{
}

PcapThread::PcapThread(pcap_t *dev, ushort port)
{
	m_pDev = dev;
	p_Port = port;

	p_PcapThread = this;
}

PcapThread::~PcapThread()
{
}


/**
 * @brief pcapLoop  ������(pcap_loop)�Ļص�����
 * @param param
 * @param header    ͨ�ð���Ϣ
 * @param pkt_data  ����������Ϣ
 */
void pcapLoop(uchar *param, const struct pcap_pkthdr *header, const uchar *pkt_data);
void pcapLoop(uchar *param, const struct pcap_pkthdr *header, const uchar *pkt_data)
{
	p_PcapThread->Loop(header, pkt_data);
}


/**
 * @brief PcapThread::run  �߳�����
 */
void PcapThread::run()
{
	//����pcap_next_ex���������ݰ�
	int res;	//��ʾ�Ƿ���յ������ݰ�
	struct pcap_pkthdr *header;		//���յ������ݰ���ͷ��
    const uchar *pkt_data;	//���յ������ݰ�������

	while ((res = pcap_next_ex(m_pDev, &header, &pkt_data)) >= 0)
	{
		if (res == 0) {
			//����ֵΪ0����������ݰ���ʱ������ѭ����������
			continue;
		}
		else
		{
			p_PcapThread->Loop(header, pkt_data);
		}
	}

	//���ûص��������ݰ���ÿ����һ֡���ݴ���pcapLoopһ��
	//pcap_loop(Dev, 0, pcapLoop, NULL);
}


/**
 * @brief PcapThread::Loop  �����񵽵����ݰ�����
 * @param header    ���ݰ�ͨ����Ϣ
 * @param pkt_data  �����ݰ�ȫ����Ϣ
 */
void PcapThread::Loop(const struct pcap_pkthdr *header, const uchar *pkt_data)
{
    static int count = 0;                   //packet counter

    // declare pointers to packet headers
    const struct sniff_ethernet *ethernet;  // The ethernet header [1]
    const struct sniff_ip *ip;              // The IP header
	int size_ip;

    // ������̫��ͷ
	ethernet = (struct sniff_ethernet*)(pkt_data);

    // ����/����IPͷƫ����
	ip = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		//qDebug() << QString("   * Invalid IP header length: %1 bytes").arg(size_ip);
		return;
	}

	_MessageContent MsgCon;
	QByteArray payload;	//��Ч�غ�����
    // ȷ��Э��
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		MsgCon = TCP(ip, size_ip, header->len, pkt_data, payload);

		if (MsgCon.Length > 0)
		{
			if (MsgCon.Length == 1 && payload.at(0) == 0x00)	//���˳���=1��������Ϊ0�����ݰ������������ֳɹ������ݰ���
				break;

			//ʱ��
			MsgCon.TimeDifference = getTimeDifference(header->ts.tv_sec, header->ts.tv_usec);
			count++;
			emit signal_PayloadData(MsgCon, payload);
		}
		break;
	case IPPROTO_UDP:
		MsgCon = UDP(ip, size_ip, pkt_data, payload);
		if (MsgCon.Length > 0)
		{
			if (MsgCon.Length == 1 && payload.at(0) == 0x00)	//���˳���=1��������Ϊ0�����ݰ������������ֳɹ������ݰ���
				break;

			//ʱ��
			MsgCon.TimeDifference = getTimeDifference(header->ts.tv_sec, header->ts.tv_usec);
			//count++;
			emit signal_PayloadData(MsgCon, payload);
		}
		return;
	case IPPROTO_ICMP:
		//qDebug() << QString("   Protocol: ICMP");
		return;
	case IPPROTO_IP:
		//qDebug() << QString("   Protocol: IP");
		return;
	default:
		//qDebug() << QString("   Protocol: unknown");
		return;
	}

	//compute time
	//struct tm *ltime;
	//char timestr[16];
	//time_t local_tv_sec;
    //// ��ʱ���ת���ɿ�ʶ��ĸ�ʽ
	//local_tv_sec = header->ts.tv_sec;
	//ltime = localtime(&local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    //// ��ӡ���ݰ���ʱ��������ݰ�����
	//qDebug() << QString("ʱ��� �룺[%1] // [%2]  /n΢�� [%3]  length:[%4]").arg(timestr).arg(header->ts.tv_sec)
	//	.arg(header->ts.tv_usec).arg(header->len);

}


/**
 * @brief PcapThread::TCP                   TCPЭ�����
 * @param[in] const sniff_ip *ip            IPͷ��Ϣ
 * @param[in] int size_ip                   IPͷ����
 * @param[in] uint len              �����ܳ���
 * @param[in] const uchar *pkt_data ���İ�����
 * @param[in] QByteArray &payload           ��������Ч������Ϣ
 * @return _MessageContent                  Э��ͷ��ϸ��Ϣ
 */
_MessageContent PcapThread::TCP(const sniff_ip *ip, int size_ip, uint len, const uchar *pkt_data , QByteArray &payload)
{
    const struct sniff_tcp *tcp;		// The TCP header
	int size_tcp;

	_MessageContent MsgCon;
	memset(&MsgCon, 0, sizeof(_MessageContent));

    // ����/����tcpͷƫ����
	tcp = (struct sniff_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		//qDebug() << QString("     Invalid TCP header length: %1 bytes").arg(size_tcp);
		return MsgCon;
	}

	//memcpy(&MsgCon.DstMACAddress, pkt_data, 6);
	//memcpy(&MsgCon.SrcMACAddress, pkt_data+6, 6);	//�����ַ
	MsgCon.type = ProtocolType::TCP;
	MsgCon.SrcAddress = ip->ip_src;
	MsgCon.DstAddress = ip->ip_dst;
	MsgCon.SrcPoet = ntohs(tcp->th_sport);
	MsgCon.DstPoet = ntohs(tcp->th_dport);

    // ������Ч�غɴ�С
	int size_payload = len - (SIZE_ETHERNET + size_ip + size_tcp);
	MsgCon.Length = size_payload;
    // ������Ч�غ�
	if (size_payload > 0) {
		//��ȡ��ȥ����ͷ+IPЭ��ͷ+TCPЭ��ͷ����֮�����ݳ���Ϊsize_payload��������Ϣ
		QByteArray tByte((char *)(pkt_data + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
		payload = tByte;

		// ��ӡ��Ч�غ���Ϣ�������Ƕ����Ƶģ����Բ�Ҫֻ�ǽ�����Ϊһ���ַ�����
		//print_payload(payload, size_payload);
	}

	return MsgCon;
}


/**
* @brief PcapThread::UDP	TCPЭ�����
* @param ip					IPͷ��Ϣ
* @param size_ip			IPͷ����
* @param pkt_data			���İ�����
* @param payload			��������Ч������Ϣ
* @return					Э��ͷ��ϸ��Ϣ
*/
_MessageContent PcapThread::UDP(const sniff_ip *ip, int size_ip, const uchar *pkt_data, QByteArray &payload)
{
    udp_header *udp_h;

	_MessageContent MsgCon;
	memset(&MsgCon, 0, sizeof(_MessageContent));

	// ����/����tcpͷƫ����
	udp_h = (struct udp_header*)(pkt_data + SIZE_ETHERNET + size_ip);

	//memcpy(&MsgCon.DstMACAddress, pkt_data, 6);
	//memcpy(&MsgCon.SrcMACAddress, pkt_data+6, 6);	//�����ַ
	MsgCon.type = ProtocolType::UDP;
	MsgCon.SrcAddress = ip->ip_src;
	MsgCon.DstAddress = ip->ip_dst;
	MsgCon.SrcPoet = ntohs(udp_h->sport);
	MsgCon.DstPoet = ntohs(udp_h->dport);

	// ������Ч�غɴ�С
	int size_payload = ntohs(udp_h->len) - 8;
	MsgCon.Length = size_payload;
	// ������Ч�غ�
	if (size_payload > 0) {
		//��ȡ��ȥ����ͷ+IPЭ��ͷ+TCPЭ��ͷ����֮�����ݳ���Ϊsize_payload��������Ϣ
		QByteArray tByte((char *)(pkt_data + SIZE_ETHERNET + size_ip + SIZE_UDPHEADER_LEN), size_payload);
		payload = tByte;
		qDebug() << payload.toHex();
	}

	return MsgCon;
}


/**
 * @brief PcapThread::print_payload  ��ӡ����Ч�غ����ݣ������ӡ���������ݣ�
 * @param payload
 * @param len
 */
void PcapThread::print_payload(const uchar *payload, int len)
{
	int len_rem = len;
    int line_width = 16;			// ÿ�е��ֽ���
	int line_len;
    int offset = 0;					// ���㿪ʼ��ƫ�Ƽ�����
    const uchar *ch = payload;

	if (len <= 0)
		return;

    // data fits on one line
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

    // data spans multiple lines
	for (;; ) {
        // ���㵱ǰ�г���
		line_len = line_width % len_rem;
        // ��ӡ��
		print_hex_ascii_line(ch, line_len, offset);
        // ����ʣ������
		len_rem = len_rem - line_len;
        // ��ָ���ƶ���Ҫ��ӡ��ʣ���ֽ�
		ch = ch + line_len;
        // ���ƫ����
		offset = offset + line_width;
        // ��������Ƿ����߿��ַ������
		if (len_rem <= line_width) {
            // ��ӡ���һ��Ȼ���뿪
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


/**
 * @brief PcapThread::print_hex_ascii_line  ��16�ֽ�Ϊ��λ��ӡ���ݣ�ƫ��ʮ������ascii
 * @param payload   ���ݰ�����
 * @param len       ���ݰ�����
 * @param offset    ���ݰ�
 */
void PcapThread::print_hex_ascii_line(const uchar *payload, int len, int offset)
{
	int i;
	int gap;
    const uchar *ch;

    // offset
	qDebug() << QString("%1   ").arg(offset);

    // hex
	ch = payload;
	for (i = 0; i < len; i++) {
		qDebug() << QString("%1 ").arg(*ch);
		ch++;
        // print extra space after 8th byte for visual aid
		if (i == 7)
			qDebug() << QString(" ");
	}
    // print space to handle line less than 8 bytes
	if (len < 8)
		qDebug() << QString(" ");

    // fill hex gap with spaces if not full line
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			qDebug() << QString("   ");
		}
	}
	qDebug() << QString("   ");

    // ascii (if printable)
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			qDebug() << QString("%1").arg(*ch);
		else
			qDebug() << QString(".");
		ch++;
	}

	qDebug() << QString("");

	return;
}


/**
 * @brief PcapThread::getTimeDifference ����ʱ���
 * @param timesec   ����
 * @param timeusec  ΢��(* 0.000001)ת��Ϊ��
 * @return ���ϸ����ݰ����ʱ��
 */
double PcapThread::getTimeDifference(long timesec ,long timeusec)
{
	static double time1 = 0;
	static double time2 = 0;
	double TimeDifference = 0.0;	//ʱ��

	if (time1 == 0)
	{
		time2 = time1 = timesec + (timeusec*0.000001);	//��¼��һ��
		return 0.0;
	}
	else
	{
		time1 = timesec + (timeusec*0.000001);
		TimeDifference = time1 - time2;		//����ʱ���
		time2 = time1;		//������ʱ����£������´μ���
	}
	return TimeDifference;
}
