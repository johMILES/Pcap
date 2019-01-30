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
	PcapCommon();
    PcapCommon(unsigned short port);
	virtual ~PcapCommon();

	void winSocketInit();
	//��ȡ������
	QVector<_DEVInfo> findAllDev();

    //������������ʼץ��
	bool openCard(const _DEVInfo);

    //�ر�ץ��
	void closeCard();

    //���ù��˶˿�
    void setPort(unsigned short port);

	//����Ĭ�ϱ���ץ���ļ�·��
    void setFilePath(QString path);

    //��ȡ���α�����ļ�����
    QString getFileName();

    //��ȡץ���ļ�
    void readDatFile(QString path);

    QString m_FilePath;   //Ĭ�ϱ����ļ�·��
    QString m_CurrentFileName;   //�����ļ�����

private slots:

private:
	pcap_if_t *m_pAlldevs;
	pcap_if_t *m_pDevs;
	pcap_t *m_pAHandle;
    unsigned short p_Port;			//���˶˿ں�

	//QThreadPool *m_pThreadPool;		//�̳߳�
	//QList<MyDealThread*> m_ListThread;

    MyDealThread *m_pDealThread;
    PcapThread *m_pPcapThread;		//ץ���߳�

	void init();

    void reset(unsigned short port = 0);
	//���ù�����
	bool setFilter(const char*, char*);

	//��ӡpcap_if_t������Ϣ
    _DEVInfo ifPcap_t(pcap_if_t*);
	/* ���������͵�IP��ַת�����ַ������͵� */
    char *iptos(unsigned long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

    QString getTime();

};

#endif // PCAPTHREAD_H
