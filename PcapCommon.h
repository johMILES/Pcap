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
	//获取适配器
	QVector<_DEVInfo> findAllDev();
	//打开
	bool openCard(const _DEVInfo);
	//关闭
	void closeCard();
	//设置端口
	void SetPort(u_short port);

	void readDatFile();

private:
	pcap_if_t *alldevs;
	pcap_if_t *devs;
	pcap_t *adHandle;
	u_short p_Port;

	//适配器个数
	int decCount;

	PcapThread *pcapThread;
	QFile *writeFile;


	void Reset();
	//设置过滤器
	bool setFilter(const char*, char*);

	//打印pcap_if_t所有信息
	void ifPcap_t(pcap_if_t*);
	/* 将数字类型的IP地址转换成字符串类型的 */
	char *iptos(u_long in);

	//获取当前时间
	QString getTime();

private slots:
	void slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload);

};

