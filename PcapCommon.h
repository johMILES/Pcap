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
	PcapCommon(u_short port);
	virtual ~PcapCommon();

	void winSocketInit();
	//��ȡ������
	QVector<_DEVInfo> findAllDev();
	//��
	bool openCard(const _DEVInfo);
	//�ر�
	void closeCard();
	//���ö˿�
	void SetPort(u_short port);

	void readDatFile();

private:
	pcap_if_t *alldevs;
	pcap_if_t *devs;
	pcap_t *adHandle;
	u_short p_Port;

	//����������
	int decCount;

	PcapThread *pcapThread;
	QFile *writeFile;


	void Reset();
	//���ù�����
	bool setFilter(const char*, char*);

	//��ӡpcap_if_t������Ϣ
	void ifPcap_t(pcap_if_t*);
	/* ���������͵�IP��ַת�����ַ������͵� */
	char *iptos(u_long in);

	//��ȡ��ǰʱ��
	QString getTime();

private slots:
	void slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload);

};

