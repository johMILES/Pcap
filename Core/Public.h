#pragma once

#ifndef _PUBLIC_
#define _PUBLIC_

#include <QString>
#include <QByteArray>

#include "winsock2.h"

//default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518

//ethernet headers are always exactly 14 bytes [1]
#define SIZE_ETHERNET 14

//Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN	6

//UDP header length 8 bytes
#define SIZE_UDPHEADER_LEN	8

//协议类型
enum ProtocolType {
	TCP,
	UDP,
	ICMP,
	IP,
	UNKNOWN
};


//Ethernet header
struct sniff_ethernet {
	unsigned char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	unsigned char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	unsigned short ether_type;                     /* IP? ARP? RARP? etc */
};

//IP header
struct sniff_ip {
	unsigned char  ip_vhl;			/* 版本 << 4 | 标题长度 >> 2 */
	unsigned char  ip_tos;			/* 服务类型 */
	unsigned short ip_len;			/* 总长度 */
	unsigned short ip_id;			/* 识别 */
	unsigned short ip_off;			/* 片段偏移字段 */
#define IP_RF 0x8000				/* 保留片段标志 */
#define IP_DF 0x4000				/* 不要碎片标志 */
#define IP_MF 0x2000				/* 更多片段标志 */
#define IP_OFFMASK 0x1fff			/* 用于分段的掩码 */
	unsigned char  ip_ttl;			/* 生存时间*/
	unsigned char  ip_p;			/* 协议 */
	unsigned short ip_sum;			/* 校验和 */
	struct  in_addr ip_src, ip_dst;	/* 源和目的地址 */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

//TCP header
typedef unsigned int tcp_seq;

struct sniff_tcp {
	unsigned short th_sport;		/* source port */
	unsigned short th_dport;		/* destination port */
	tcp_seq th_seq;					/* sequence number */
	tcp_seq th_ack;					/* acknowledgement number */
	unsigned char  th_offx2;		/* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	unsigned char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short th_win;			/* window */
	unsigned short th_sum;			/* checksum */
	unsigned short th_urp;			/* urgent pointer */
};

//UDP 首部
typedef struct UDP_HEADER{
	unsigned short sport;          // 源端口(Source port)
	unsigned short dport;          // 目的端口(Destination port)
	unsigned short len;            // UDP数据包长度(Datagram length)
	unsigned short crc;            // 校验和(Checksum)
}udp_header;

typedef struct _MessageContent
{
    _MessageContent()
	{
		Type = UNKNOWN;
		SrcAddress = { 0 };
		DstAddress = { 0 };
		SrcPoet = 0;
		DstPoet = 0;
		Length = 0;
		TimeDifference = 0;
		Data.clear();
	}
	ProtocolType Type;			//类型
	struct in_addr SrcAddress;
	struct in_addr DstAddress;	//收发IP地址
	unsigned short SrcPoet;		//源端口号
	unsigned short DstPoet;		//目的端口号
	unsigned short Length;		//报文有效载荷长度
	double TimeDifference;		//相隔时间
	QByteArray Data;			//数据

}MessageContent;


typedef struct __LocalCardInfo
{
    QString humanReadableName;
    QString ip;
}_LocalCardInfo;

typedef struct __DEVInfo {
	QString name;
	QString description;
	QString familyName;		//协议族
	QString address;		//主机ip
	QString netmask;		//子网掩码
}_DEVInfo;



#endif	/* _PUBLIC_ */
