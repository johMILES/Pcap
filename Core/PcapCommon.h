#pragma once

#ifndef PCAPCOMMON_H
#define PCAPCOMMON_H

//#define HVAE_REMOTE
#include "pcap.h"
#include "PcapThread.h"
#include "Public.h"
#include "mydealthread.h"

#include <QObject>
#include <QVector>

class PcapCommon : public QObject
{
	Q_OBJECT
public:
    static PcapCommon* getInstance();

	void winSocketInit();
	//��ȡ������
    QVector<_DEVInfo> getAllDev();

    //������������ʼץ��
	bool openCard(const _DEVInfo);

    //��ʼ����
    void startCapturing(const _DEVInfo in_DevInfo);

    //�������ݰ�
    void sendData(QByteArray,QByteArray,QByteArray,unsigned short,unsigned short);

    //�ر�ץ��
	void closeCard();

    //���ù��˶˿�
    void setPort(unsigned short port);

	//����Ĭ�ϱ���ץ���ļ�·��
    void setFilePath(QString path);

    //��ȡ���α�����ļ�����
    QString getFileName();

    //��ȡpcapָ��
    pcap_t* getPcap_t();

    QString m_FilePath;   //Ĭ�ϱ����ļ�·��
    QString m_CurrentFileName;   //�����ļ�����

private slots:

private:
    PcapCommon();
    PcapCommon(unsigned short port);
    virtual ~PcapCommon();

	pcap_if_t *m_pAlldevs;
	pcap_if_t *m_pDevs;
	pcap_t *m_pAHandle;

    unsigned short p_Port;			//���˶˿ں�
    QVector<_DEVInfo> m_pDecs_List;    //�������б�
	//QThreadPool *m_pThreadPool;		//�̳߳�
	//QList<MyDealThread*> m_ListThread;

    MyDealThread *m_pDealThread;
    PcapThread *m_pPcapThread;		//ץ���߳�

    void reset(unsigned short port = 0);
	//���ù�����
	bool setFilter(const char*, char*);
    void selectAllDev();

	//��ӡpcap_if_t������Ϣ
    _DEVInfo ifPcap_t(pcap_if_t*);

    unsigned short check_UDP_sum(unsigned short *a, int len);
    unsigned short in_cksum(unsigned short *addr, int len);

    unsigned short tcpip_chksum(unsigned short initcksum, unsigned char* data, int datalen);
    int tcp_checksum(uint8_t* tcphdr, int tcplen, uint32_t* srcaddr, uint32_t* dstaddr);

	/* ���������͵�IP��ַת�����ַ������͵� */
    char* iptos(unsigned long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

    QString getTime();

};

#endif // PCAPTHREAD_H
