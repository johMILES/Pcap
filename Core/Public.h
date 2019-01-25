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

//Э������
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
	u_char  ip_vhl;					/* �汾 << 4 | ���ⳤ�� >> 2 */
	u_char  ip_tos;					/* �������� */
	u_short ip_len;					/* �ܳ��� */
	u_short ip_id;					/* ʶ�� */
	u_short ip_off;					/* Ƭ��ƫ���ֶ� */
#define IP_RF 0x8000				/* ����Ƭ�α�־ */
#define IP_DF 0x4000				/* ��Ҫ��Ƭ��־ */
#define IP_MF 0x2000				/* ����Ƭ�α�־ */
#define IP_OFFMASK 0x1fff			/* ���ڷֶε����� */
	u_char  ip_ttl;					/* ����ʱ��*/
	u_char  ip_p;					/* Э�� */
	u_short ip_sum;					/* У��� */
	struct  in_addr ip_src, ip_dst;	/* Դ��Ŀ�ĵ�ַ */
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
	//char DstMACAddress[6];	//�շ�MAC��ַ
	ProtocolType type;			//����
	struct in_addr SrcAddress;
	struct in_addr DstAddress;	//�շ�IP��ַ
	u_short SrcPoet;
	u_short DstPoet;			//�շ�Port
	u_short Length;				//������Ч�غɳ���
	double TimeDifference;		//����ʱ��
}_MessageContent;


typedef struct __LocalCardInfo
{
    QString humanReadableName;
    QString ip;
}_LocalCardInfo;

typedef struct __DEVInfo {
	QString name;
	QString description;
	QString familyName;         //Э����
	QString address;            //����ip
	QString netmask;            //��������
}_DEVInfo;


/* 4�ֽڵ�IP��ַ */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 �ײ� */
typedef struct ip_header {
	u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
	u_char  tos;            // ��������(Type of service) 
	u_short tlen;           // �ܳ�(Total length) 
	u_short identification; // ��ʶ(Identification)
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;            // ���ʱ��(Time to live)
	u_char  proto;          // Э��(Protocol)
	u_short crc;            // �ײ�У���(Header checksum)
	ip_address  saddr;      // Դ��ַ(Source address)
	ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
	u_int   op_pad;         // ѡ�������(Option + Padding)
}ip_header;

/* tcp �ײ� */
typedef struct tcp_header {
	u_short sport;         //Դ�˿�
	u_short dport;         //Ŀ�Ķ˿�
	u_int th_seq;             //���к�
	u_int th_ack;             //ȷ�Ϻ�
	u_short doff : 4, hlen : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1; //4 bits �ײ����ȣ�6 bits ����λ��6 bits ��־λ
	u_short th_window;        //���ڴ�С
	u_short th_sum;           //У���
	u_short th_urp;           //����ָ��
}tcp_header;

/* UDP �ײ�*/
typedef struct udp_header {
	u_short sport;          // Դ�˿�(Source port)
	u_short dport;          // Ŀ�Ķ˿�(Destination port)
	u_short len;            // UDP���ݰ�����(Datagram length)
	u_short crc;            // У���(Checksum)
}udp_header;

#endif	/* _PUBLIC_ */
