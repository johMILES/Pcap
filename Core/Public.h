#pragma once

#ifndef _PUBLIC_
#define _PUBLIC_

#include <QString>
#include "winsock2.h"


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

//UDP header length 8 bytes
#define SIZE_UDPHEADER_LEN	8

//协议类型
enum ProtocolType {
	TCP,
	UDP,
	ICMP,
	IP
};


//Ethernet header
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;					/* 版本 << 4 | 标题长度 >> 2 */
	u_char  ip_tos;					/* 服务类型 */
	u_short ip_len;					/* 总长度 */
	u_short ip_id;					/* 识别 */
	u_short ip_off;					/* 片段偏移字段 */
#define IP_RF 0x8000				/* 保留片段标志 */
#define IP_DF 0x4000				/* 不要碎片标志 */
#define IP_MF 0x2000				/* 更多片段标志 */
#define IP_OFFMASK 0x1fff			/* 用于分段的掩码 */
	u_char  ip_ttl;					/* 生存时间*/
	u_char  ip_p;					/* 协议 */
	u_short ip_sum;					/* 校验和 */
	struct  in_addr ip_src, ip_dst;	/* 源和目的地址 */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};



typedef struct __MessageContent
{
	//char SrcMACAddress[6];
	//char DstMACAddress[6];	//收发MAC地址
	ProtocolType type;			//类型
	struct in_addr SrcAddress;
	struct in_addr DstAddress;	//收发IP地址
	u_short SrcPoet;
	u_short DstPoet;			//收发Port
	u_short Length;				//报文有效载荷长度
	double TimeDifference;		//报文时差
}_MessageContent;


typedef struct __LocalCardInfo
{
    QString humanReadableName;
    QString ip;
}_LocalCardInfo;

typedef struct __DEVInfo {
	QString name;
	QString description;
	QString familyName;         //协议族
	QString address;            //主机ip
	QString netmask;            //子网掩码
}_DEVInfo;


/* 4字节的IP地址 */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header {
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* tcp 首部 */
typedef struct tcp_header {
	u_short sport;         //源端口
	u_short dport;         //目的端口
	u_int th_seq;             //序列号
	u_int th_ack;             //确认号
	u_short doff : 4, hlen : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1; //4 bits 首部长度，6 bits 保留位，6 bits 标志位
	u_short th_window;        //窗口大小
	u_short th_sum;           //校验和
	u_short th_urp;           //紧急指针
}tcp_header;

/* UDP 首部*/
typedef struct udp_header {
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;

#endif	/* _PUBLIC_ */
