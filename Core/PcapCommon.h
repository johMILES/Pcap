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
	//获取适配器
	QVector<_DEVInfo> findAllDev();

    //打开适配器，开始抓包
	bool openCard(const _DEVInfo);

    //关闭抓包
	void closeCard();

    //设置过滤端口
    void setPort(unsigned short port);

	//设置默认保存抓包文件路径
    void setFilePath(QString path);

    //获取本次保存的文件名称
    QString getFileName();

    //读取抓包文件
    void readDatFile(QString path);

    QString m_FilePath;   //默认保存文件路径
    QString m_CurrentFileName;   //保存文件名称

private slots:

private:
	pcap_if_t *m_pAlldevs;
	pcap_if_t *m_pDevs;
	pcap_t *m_pAHandle;
    unsigned short p_Port;			//过滤端口号

	//QThreadPool *m_pThreadPool;		//线程池
	//QList<MyDealThread*> m_ListThread;

    MyDealThread *m_pDealThread;
    PcapThread *m_pPcapThread;		//抓包线程

	void init();

    void reset(unsigned short port = 0);
	//设置过滤器
	bool setFilter(const char*, char*);

	//打印pcap_if_t所有信息
    _DEVInfo ifPcap_t(pcap_if_t*);
	/* 将数字类型的IP地址转换成字符串类型的 */
    char *iptos(unsigned long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

    QString getTime();

};

#endif // PCAPTHREAD_H
