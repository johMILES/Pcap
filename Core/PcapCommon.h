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
	//获取适配器
	QVector<_DEVInfo> findAllDev();
    //打开适配器，开始抓包
	bool openCard(const _DEVInfo);
    //关闭抓包
	void closeCard();
    //设置过滤端口
    void setPort(unsigned short port);
    void setFilePath(QString path);

    //获取本次保存的文件名称
    QString getFileName();

    //读取抓包文件
    void readDatFile(QString path);

    QString m_FilePath;   //默认保存文件路径
    QString m_CurrentFileName;   //默认保存文件路径

private:
	pcap_if_t *m_pAlldevs;
	pcap_if_t *m_pDevs;
	pcap_t *m_pAHandle;
    unsigned short p_Port;

	//适配器个数
	int decCount;

	PcapThread *m_pPcapThread;
	QFile *m_pWriteFile;

    QByteArray HexStringToByteArray(QString);
    QString ByteArrayToHexString(QByteArray &ba);

	void reset();
	//设置过滤器
	bool setFilter(const char*, char*);

	//打印pcap_if_t所有信息
    _DEVInfo ifPcap_t(pcap_if_t*);
	/* 将数字类型的IP地址转换成字符串类型的 */
    char *iptos(unsigned long in);
    char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

    QString getTime();

private slots:
	void slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload);

};

