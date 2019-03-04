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
	//获取适配器
    QVector<_DEVInfo> getAllDev();

    //打开适配器，开始抓包
	bool openCard(const _DEVInfo);

    //开始捕获
    void startCapturing(const _DEVInfo in_DevInfo);

    //发送数据包
    void sendData(QByteArray,QByteArray,QByteArray,unsigned short,unsigned short);

    //关闭抓包
	void closeCard();

    //设置过滤端口
    void setPort(unsigned short port);

	//设置默认保存抓包文件路径
    void setFilePath(QString path);

    //获取本次保存的文件名称
    QString getFileName();

    //获取pcap指针
    pcap_t* getPcap_t();

    QString m_FilePath;   //默认保存文件路径
    QString m_CurrentFileName;   //保存文件名称

private slots:

private:
    PcapCommon();
    PcapCommon(unsigned short port);
    virtual ~PcapCommon();

	pcap_if_t *m_pAlldevs;
	pcap_if_t *m_pDevs;
	pcap_t *m_pAHandle;

    unsigned short p_Port;			//过滤端口号
    QVector<_DEVInfo> m_pDecs_List;    //适配器列表
	//QThreadPool *m_pThreadPool;		//线程池
	//QList<MyDealThread*> m_ListThread;

    MyDealThread *m_pDealThread;
    PcapThread *m_pPcapThread;		//抓包线程

    void reset(unsigned short port = 0);
	//设置过滤器
	bool setFilter(const char*, char*);
    void selectAllDev();

	//打印pcap_if_t所有信息
    _DEVInfo ifPcap_t(pcap_if_t*);

    unsigned short check_UDP_sum(unsigned short *a, int len);
    unsigned short in_cksum(unsigned short *addr, int len);

    unsigned short tcpip_chksum(unsigned short initcksum, unsigned char* data, int datalen);
    int tcp_checksum(uint8_t* tcphdr, int tcplen, uint32_t* srcaddr, uint32_t* dstaddr);

	/* 将数字类型的IP地址转换成字符串类型的 */
    char* iptos(unsigned long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

    QString getTime();

};

#endif // PCAPTHREAD_H
