#include "PcapThread.h"

#include <QDebug>
#include <QLatin1String>
#include <QByteArray>
#include <QString>

PcapThread *p_PcapThread = NULL;
PcapThread::PcapThread()
{
}

PcapThread::PcapThread(pcap_t *dev, u_short port)
{
	m_pDev = dev;
	p_Port = port;

	p_PcapThread = this;
}

PcapThread::~PcapThread()
{
}

void pcapLoop(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void pcapLoop(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	p_PcapThread->Loop(header, pkt_data);
}

//开始抓包
void PcapThread::run()
{
	//利用pcap_next_ex来接受数据包
	int res;	//表示是否接收到了数据包
	struct pcap_pkthdr *header;		//接收到的数据包的头部
	const u_char *pkt_data;			//接收到的数据包的内容

	while ((res = pcap_next_ex(m_pDev, &header, &pkt_data)) >= 0)
	{
		if (res == 0) {
			//返回值为0代表接受数据包超时，重新循环继续接收
			continue;
		}
		else
		{
			p_PcapThread->Loop(header, pkt_data);
		}
	}

	//利用回调捕获数据包，每捕获一帧数据触发pcapLoop一次
	//pcap_loop(Dev, 0, pcapLoop, NULL);
}


void PcapThread::Loop(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	static int count = 0;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	int size_ip;

	/* 定义以太网头 */
	ethernet = (struct sniff_ethernet*)(pkt_data);

	/* 定义/计算IP头偏移量 */
	ip = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		//qDebug() << QString("   * Invalid IP header length: %1 bytes").arg(size_ip);
		return;
	}

	_MessageContent MsgCon;
	QByteArray payload;	//有效载荷数据
	/* 确定协议 */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		MsgCon = TCP(ip, size_ip, header->len, pkt_data, payload);

		//时差
		MsgCon.TimeDifference = getTimeDifference(header->ts.tv_sec, header->ts.tv_usec);

		if (MsgCon.Length > 0)
		{
			if (MsgCon.Length == 1 && payload.at(0) == 0x00)	//过滤长度=1并且数据为0的数据包（可能是握手成功的数据包）
				break;

			count++;
			emit signal_Data(MsgCon, payload);
		}
		break;
	case IPPROTO_UDP:
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
	///* 将时间戳转换成可识别的格式 */
	//local_tv_sec = header->ts.tv_sec;
	//ltime = localtime(&local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	///* 打印数据包的时间戳和数据包长度 */
	//qDebug() << QString("时间戳 秒：[%1] // [%2]  /n微秒 [%3]  length:[%4]").arg(timestr).arg(header->ts.tv_sec)
	//	.arg(header->ts.tv_usec).arg(header->len);

}


/*
方法说明：
	TCP 协议解析

参数信息：
	const sniff_ip *ip		//IP头
	int size_ip				//IP头大小
	u_int len				//报文总长度
	const u_char *pkt_data	//报文包数据
	QByteArray &payload		//解析后的数据信息

返回值：
	协议头详细信息
*/
_MessageContent PcapThread::TCP(const sniff_ip *ip, int size_ip, u_int len, const u_char *pkt_data , QByteArray &payload)
{
	const struct sniff_tcp *tcp;		/* The TCP header */
	int size_tcp;

	_MessageContent MsgCon;
	memset(&MsgCon, 0, sizeof(_MessageContent));

	/* 定义/计算tcp头偏移量 */
	tcp = (struct sniff_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		//qDebug() << QString("     Invalid TCP header length: %1 bytes").arg(size_tcp);
		return MsgCon;
	}

	memcpy(&MsgCon.DstMACAddress, pkt_data, 6);
	memcpy(&MsgCon.SrcMACAddress, pkt_data+6, 6);	//物理地址
	MsgCon.SrcAddress = ip->ip_src;
	MsgCon.DstAddress = ip->ip_dst;
	MsgCon.SrcPoet = ntohs(tcp->th_sport);
	MsgCon.DstPoet = ntohs(tcp->th_dport);

	/* 打印源和目标IP地址 */
	/*qDebug() << QString("IP Address: [%1] -> [%2]").arg(inet_ntoa(ip->ip_src)).arg(inet_ntoa(ip->ip_dst));
	// 打印端口号
	qDebug() << QString("      Port: [%1] -> [%2]").arg(ntohs(tcp->th_sport)).arg(ntohs(tcp->th_dport));
	*/

	/* 计算有效载荷大小 */
	int size_payload = len - (SIZE_ETHERNET + size_ip + size_tcp);
	MsgCon.Length = size_payload;
	/* 计算有效载荷 */
	if (size_payload > 0) {
		//获取除去IP头+IP协议头+TCP协议头长度之后数据长度为size_payload的数据信息
		QByteArray tByte((char *)(pkt_data + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
		payload = tByte;

		// 打印有效载荷信息它可能是二进制的，所以不要只是将其视为一个字符串。
		//print_payload(payload, size_payload);
	}

	return MsgCon;
}

void PcapThread::UDP(const u_char *pkt_data)
{
	ip_header *ih;
	udp_header *udp_h;
	u_int ip_len;
	u_int udp_len;
	u_short sport, dport;

	/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data + SIZE_ETHERNET); //以太网头部长度
	ip_len = (ih->ver_ihl & 0xf) * 4;
	if (ip_len < 20)
	{
		return;
	}

	/* 获得TCP首部的位置 */
	udp_h = (udp_header *)((u_char*)ih +ip_len);

	/* 将网络字节序列转换成主机字节序列 */
	sport = ntohs(udp_h->sport);	//源端口
	dport = ntohs(udp_h->dport);	//目的端口

}

/*
* 打印包有效载荷数据（避免打印二进制数据）
*/
void PcapThread::print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
* 以16字节为单位打印数据：偏移十六进制ascii
*
* 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
*/
void PcapThread::print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	qDebug() << QString("%1   ").arg(offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		qDebug() << QString("%1 ").arg(*ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			qDebug() << QString(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		qDebug() << QString(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			qDebug() << QString("   ");
		}
	}
	qDebug() << QString("   ");

	/* ascii (if printable) */
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
 * 计算时间差
 *
 * long timesec		秒数
 * long usec		微秒(* 0.000001)转换为秒
 */
double PcapThread::getTimeDifference(long timesec ,long timeusec)
{
	static double time1 = 0;
	static double time2 = 0;
	double TimeDifference = 0.0;	//时间

	if (time1 == 0)
	{
		time2 = time1 = timesec + (timeusec*0.000001);	//记录第一次
		return 0.0;
	}
	else
	{
		time1 = timesec + (timeusec*0.000001);
		TimeDifference = time1 - time2;		//计算时间差
		time2 = time1;		//将本次时间更新，方便下次计算
	}
	return TimeDifference;
}