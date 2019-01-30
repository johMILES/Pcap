#include "PcapCommon.h"
#include "gloab.h"

#include <QDebug>
#include <QThread>
#include <QApplication>
#include <QDateTime>
#include <QDataStream>
#include <QtNetwork/QNetworkInterface>

#include <windows.h>
#include <winsock.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "packet.lib")


PcapCommon::PcapCommon()
{
    reset();
    init();
}

PcapCommon::PcapCommon(unsigned short port)
{
    reset(port);
    init();
}


PcapCommon::~PcapCommon()
{
    closeCard();
    pcap_freealldevs(m_pAlldevs);
}

void PcapCommon::reset(unsigned short port)
{
    p_Port = port;

    m_pAlldevs = NULL;
    m_pDevs = NULL;
    m_pAHandle = NULL;
    m_pPcapThread = NULL;
    m_pDealThread = NULL;

    //TODO: 保留
    //m_ListThread.clear();
    //m_pThreadPool = NULL;
}


void PcapCommon::init()
{
    //m_pThreadPool = new QThreadPool;
    //m_pThreadPool->setMaxThreadCount(3);
    //启动记录文件线程

    connect(m_pPcapThread, &QThread::finished, m_pPcapThread, &QObject::deleteLater);
}


/*!
 * @brief PcapCommon::winSocketInit 初始化Winsock
 * @param NULL
 * @return void
 */
void PcapCommon::winSocketInit()
{
    WSADATA wsaData;
    // 调用Windows Sockets DLL
    if (WSAStartup(MAKEWORD(2, 1), &wsaData)) {
        qDebug() << "Winsock无法初始化!";
        WSACleanup();
        return;
    }
}


/*!
 * @brief PcapCommon::findAllDev
 * @return
 */
QVector<_DEVInfo> PcapCommon::findAllDev()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&m_pAlldevs, errbuf) == -1) {
        qDebug() << errbuf;
        pcap_freealldevs(m_pAlldevs);
        exit(1);
    }

    QList<_LocalCardInfo> cardList;
    QList<QNetworkInterface> list = QNetworkInterface::allInterfaces();
    foreach (QNetworkInterface netInterface, list)
    {
        if (!netInterface.isValid())
            continue;

        _LocalCardInfo card;
        card.humanReadableName = netInterface.humanReadableName();  //可读的名字

        QNetworkAddressEntry entry= netInterface.addressEntries().last();
        card.ip = entry.ip().toString();
        if (card.ip.length() > 15)
            continue;
        cardList.append(card);
    }

    QVector<_DEVInfo> dec_List;
    for (m_pDevs = m_pAlldevs; m_pDevs; m_pDevs = m_pDevs->next)
    {
        dec_List.append(ifPcap_t(m_pDevs));
    }

    //对比两次获取适配器IP是否相同 相同则替换适配器名称
    QVector<_DEVInfo> decs_List;
    for (int i = 0; i< dec_List.count(); i++)
    {
        for (int j = 0; j < cardList.count(); j++)
        {
            if (dec_List.at(i).address == cardList.at(j).ip)
            {
                _DEVInfo dev = dec_List.at(i);
                dev.description = cardList.at(j).humanReadableName;
                //cardList.removeAt(j);
                decs_List.append(dev);
                break;
            }
        }
    }

    return decs_List;
}


/*!
 * @brief PcapCommon::openCard 开启进程开始捕获数据
 * @param const _DEVInfo DevInfo
 * @return bool 是否正常启动抓包功能
 */
bool PcapCommon::openCard(const _DEVInfo  in_DevInfo)
{
    char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区

    //打开适配器
    m_pAHandle = pcap_open_live(
                in_DevInfo.name.toUtf8().data(),	//设备名
                65535,                              //要捕捉的数据包的部分	65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                PCAP_OPENFLAG_PROMISCUOUS,          //设置混杂模式
                1000,                               //读取超时时间
                errbuf );                           //错误缓冲池

    if (m_pAHandle == NULL)
    {
        qDebug() << stderr << QString("Unable to open the adapter. [%1] is not supported by WinPcap").arg(m_pDevs->name);
        pcap_freealldevs(m_pAlldevs);
        return false;
    }

    //设置过滤条件
    QByteArray tFilter("ip and tcp and port ");
    tFilter.append(QString("%1").arg(p_Port));
    //设置过滤器
    if (!setFilter(in_DevInfo.netmask.toUtf8().data(), tFilter.data()))
    {
        return false;
    }

	//记录数据消费者线程
	m_pDealThread = new MyDealThread(m_FilePath, this);
	m_pDealThread->start();

    //启动抓包线程
	m_pPcapThread = new PcapThread(m_pAHandle, p_Port);
	m_pPcapThread->start();
	return true;
}

/*!
 * @brief PcapCommon::closeCard 关闭pcap并结束抓包进程，保存文件
 * @param NULL
 * @return void
 */
void PcapCommon::closeCard()
{
    if (m_pAHandle != NULL)
    {
        pcap_close(m_pAHandle);
        m_pAHandle = NULL;
    }

    if(m_pPcapThread != NULL)
    {
        m_pPcapThread->wait();
        delete m_pPcapThread;
        m_pPcapThread = NULL;
    }
	if (m_pDevs != NULL)
	{
		m_pDevs = NULL;
	}
}

/*!
 * @brief PcapCommon::SetPort 设置端口过滤
 * @param unsigned short port
 * @return void
 */
void PcapCommon::setPort(unsigned short port)
{
    p_Port = port;
}


/*!
 * @brief PcapCommon::setFilePath   设置存放文件路径
 * @param path  最后一次抓包保存文件的路径
 */
void PcapCommon::setFilePath(QString path)
{
    //为设置路径添加文件名称
    m_CurrentFileName = getTime()+".dat";
    m_FilePath+=path+"/"+m_CurrentFileName;
}


/*!
 * @brief PcapCommon::getFileName  获取本次保存的文件名称
 * @return  最后一次抓包结束保存文件的文件名
 */
QString PcapCommon::getFileName()
{
    return m_CurrentFileName;
}


/*!
 * @brief PcapCommon::readDatFile 读取保存的文件
 */
void PcapCommon::readDatFile(QString path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return;

    QDataStream out(&file);
    while (!out.atEnd())
    {
        QByteArray src_ip;
        QByteArray dst_ip;
        QByteArray payload;

        ushort SrcPoet;
        ushort DstPoet;                 //收发Port
        QByteArray TimeDifference;		//报文时差

        out >> src_ip >> dst_ip
                >> SrcPoet >> DstPoet >> TimeDifference >> payload;

        char * data = { 0 };
        data = (char*)malloc(payload.length());
        memset(data, 0, payload.length());

        data = payload.data();
        data = NULL;
        free(data);
    }

    file.close();
}


/*!
 * @brief PcapCommon::setFilter   设置过滤器
 * @param const char *netmask     掩码
 * @param char* packet_filter     过滤条件
 * @return bool true:设置成功 false:设置失败
 */
bool PcapCommon::setFilter(const char* netmask, char* packet_filter)
{
    unsigned int ui_netmask = QString(netmask).toInt();
    struct bpf_program fcode;
    //编译过滤器
    if (pcap_compile(m_pAHandle, &fcode, packet_filter, 1, ui_netmask) < 0)
    {
        qDebug() << stderr, "Unable to compile thepacket filter. Check the syntax.";
        pcap_freealldevs(m_pAlldevs);
        return false;
    }

    //设置过滤器
    if (pcap_setfilter(m_pAHandle, &fcode) < 0)
    {
        qDebug() << "Error setting thefilter";
        pcap_freealldevs(m_pAlldevs);
        return false;
    }
    return true;
}


/*!
 * @brief PcapCommon::ifPcap_t  打印该适配器所有可用的信息
 * @param d
 */
_DEVInfo PcapCommon::ifPcap_t(pcap_if_t *d)
{
    _DEVInfo Dev;
    pcap_addr_t *a;

    Dev.name = d->name;
    //    qDebug() << d->name;

    if (d->description)
    {
        Dev.description = d->description;
        //        qDebug() << "Description:" << d->description;
    }

    //回环地址
    //    qDebug() << QString("%1").arg((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    for (a = d->addresses; a; a = a->next) {
        //        qDebug() << QString("Address Family: #%1").arg(a->addr->sa_family);

        switch (a->addr->sa_family)
        {
        case AF_INET:
            Dev.familyName = "AF_INET";
            //            qDebug() << QString("--------------AF_INET--------------");  //打印网络地址类型
            if (a->addr)		//打印IP地址
            {
                Dev.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                //                qDebug() << QString("Address: %1").arg(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            }
            if (a->netmask)		//打印掩码
            {
                Dev.netmask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                //                qDebug() << QString("Netmask: %1").arg(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            }
            //            if (a->broadaddr)	//打印广播地址
            //                qDebug() << QString("\tBroadcast Address: %1 ").arg(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            //            if (a->dstaddr)		//目的地址
            //                qDebug() << QString("Destination Address: %1 ").arg(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            break;
            //        case AF_INET6:
            //            qDebug()<<"------------AF_INET6-----------------";
            //            if (a->addr)
            //                QString("Address: %1").arg(ip6tos(a->addr, ip6str, sizeof(ip6str)));
            //            break;
        default:
            //            qDebug() << QString("Address Family Name: Unknown ");
            break;
        }
    }
    return Dev;
}


#define IPTOSBUFFERS    12

/*!
 * @brief PcapCommon::iptos  将数字类型的IP地址转换成字符串类型的
 * @param in  IP
 * @return    转换后IP
 */
char* PcapCommon::iptos(unsigned long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    unsigned char *p;

    p = (unsigned char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}


/*!
 * @brief ip6tos
 * @param sockaddr
 * @param address
 * @param addrlen
 * @return
 */
char* PcapCommon::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   addrlen,
                   NULL,
                   0,
                   NI_NUMERICHOST) != 0) address = NULL;

    return address;
}


/*!
 * @brief PcapCommon::getTime   获取当前时间
 * @return  年月日-时分秒
 */
QString PcapCommon::getTime()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh.mm.ss");
}




















