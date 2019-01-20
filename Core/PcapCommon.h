#pragma once

//#define HVAE_REMOTE
#include "pcap.h"
#include "PcapThread.h"
#include "Public.h"

#include <QObject>
#include <QString>
#include <QVector>
#include <QFile>


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
    void setFilePath(QString path);

    //��ȡץ���ļ�
    void readDatFile(QString path);

    QString m_SelectPath;   //Ĭ�ϱ����ļ�·��

private:
	pcap_if_t *m_pAlldevs;
	pcap_if_t *m_pDevs;
	pcap_t *m_pAHandle;
    unsigned short p_Port;

	//����������
	int decCount;

	PcapThread *m_pPcapThread;
	QFile *m_pWriteFile;


	void reset();
	//���ù�����
	bool setFilter(const char*, char*);

	//��ӡpcap_if_t������Ϣ
	void ifPcap_t(pcap_if_t*);
	/* ���������͵�IP��ַת�����ַ������͵� */
    char *iptos(unsigned long in);

    QString getTime();

private slots:
	void slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload);

};

