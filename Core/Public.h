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

//Э������
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
	unsigned char  ip_vhl;			/* �汾 << 4 | ���ⳤ�� >> 2 */
	unsigned char  ip_tos;			/* �������� */
	unsigned short ip_len;			/* �ܳ��� */
	unsigned short ip_id;			/* ʶ�� */
	unsigned short ip_off;			/* Ƭ��ƫ���ֶ� */
#define IP_RF 0x8000				/* ����Ƭ�α�־ */
#define IP_DF 0x4000				/* ��Ҫ��Ƭ��־ */
#define IP_MF 0x2000				/* ����Ƭ�α�־ */
#define IP_OFFMASK 0x1fff			/* ���ڷֶε����� */
	unsigned char  ip_ttl;			/* ����ʱ��*/
	unsigned char  ip_p;			/* Э�� */
	unsigned short ip_sum;			/* У��� */
	struct  in_addr ip_src, ip_dst;	/* Դ��Ŀ�ĵ�ַ */
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

//UDP �ײ�
typedef struct UDP_HEADER{
	unsigned short sport;          // Դ�˿�(Source port)
	unsigned short dport;          // Ŀ�Ķ˿�(Destination port)
	unsigned short len;            // UDP���ݰ�����(Datagram length)
	unsigned short crc;            // У���(Checksum)
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
	ProtocolType Type;			//����
	struct in_addr SrcAddress;
	struct in_addr DstAddress;	//�շ�IP��ַ
	unsigned short SrcPoet;		//Դ�˿ں�
	unsigned short DstPoet;		//Ŀ�Ķ˿ں�
	unsigned short Length;		//������Ч�غɳ���
	double TimeDifference;		//���ʱ��
	QByteArray Data;			//����

}MessageContent;


typedef struct __LocalCardInfo
{
    QString humanReadableName;
    QString ip;
}_LocalCardInfo;

typedef struct __DEVInfo {
	QString name;
	QString description;
	QString familyName;		//Э����
	QString address;		//����ip
	QString netmask;		//��������
}_DEVInfo;



#endif	/* _PUBLIC_ */
