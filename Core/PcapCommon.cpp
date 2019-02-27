#include "PcapCommon.h"

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

#include "gloab.h"
#include "Base/messaging.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "packet.lib")


static PcapCommon *g_pPcapCommon = NULL;
PcapCommon::PcapCommon()
{
    reset();
    winSocketInit();
    selectAllDev();
}

PcapCommon::PcapCommon(unsigned short port)
{
    reset(port);
    winSocketInit();
    selectAllDev();
}


PcapCommon::~PcapCommon()
{
    closeCard();
    pcap_freealldevs(m_pAlldevs);
}


PcapCommon* PcapCommon::getInstance()
{
    if (!g_pPcapCommon)
        new PcapCommon();

    return g_pPcapCommon;
}

/**
 * @brief PcapCommon::reset  重置
 * @param port  抓包过滤端口号
 */
void PcapCommon::reset(unsigned short port)
{
    g_pPcapCommon = this;
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


/**
 * @brief PcapCommon::winSocketInit  初始化Winsock
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


/**
 * @brief PcapCommon::selectAllDev  查找所有适配器
 */
void PcapCommon::selectAllDev()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&m_pAlldevs, errbuf) == -1)
    {
//        qDebug() << errbuf;
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

    m_pDecs_List.clear();
    //对比两次获取适配器IP是否相同 相同则替换适配器名称
    for (int i = 0; i< dec_List.count(); i++)
    {
        for (int j = 0; j < cardList.count(); j++)
        {
            if (dec_List.at(i).address == cardList.at(j).ip)
            {
                _DEVInfo dev = dec_List.at(i);
                dev.description = cardList.at(j).humanReadableName;
                //cardList.removeAt(j);
                m_pDecs_List.append(dev);
                break;
            }
        }
    }
}

/**
 * @brief PcapCommon::getAllDev    查询当前计算机的适配器信息
 * @return
 */
QVector<_DEVInfo> PcapCommon::getAllDev()
{
    return m_pDecs_List;
}


/**
 * @brief PcapCommon::openCard  开启进程开始捕获数据
 * @param in_DevInfo    适配器信息
 * @return              是否正常启动抓包功能
 */
bool PcapCommon::openCard(const _DEVInfo in_DevInfo)
{
    char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区
    static bool t_bIsOpenFalg = false;

    if (t_bIsOpenFalg)
        return t_bIsOpenFalg;

    //打开适配器
    m_pAHandle = pcap_open(
                in_DevInfo.name.toUtf8().data(),	//设备名
                65535,                              //要捕捉的数据包的部分	65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                PCAP_OPENFLAG_PROMISCUOUS,          //设置混杂模式
                3000,                               //读取超时时间
                NULL,                               //远程机器验证
                errbuf );                           //错误缓冲池

    if (m_pAHandle == NULL)
    {
        Messaging::getInstance()->messageMenubar(
                    QString(tr("Unable to open the adapter. [%1] is not supported by WinPcap").arg(m_pDevs->name)));
//        qDebug() << stderr << QString("Unable to open the adapter. [%1] is not supported by WinPcap").arg(m_pDevs->name);
        pcap_freealldevs(m_pAlldevs);
        t_bIsOpenFalg = false;
        return false;
    }

    t_bIsOpenFalg = true;
    return t_bIsOpenFalg;
}


/**
 * @brief PcapCommon::startCapturing
 */
void PcapCommon::startCapturing(const _DEVInfo in_DevInfo)
{
    //设置过滤条件
    QByteArray tFilter("ip and tcp and port ");
    tFilter.append(QString("%1").arg(p_Port));
    //设置过滤器
    if (!setFilter(in_DevInfo.netmask.toUtf8().data(), tFilter.data()))
    {
        Messaging::getInstance()->messageMenubar(tr("Filter condition error"));
        return;
    }

    //记录数据消费者线程
    if (m_pDealThread == NULL)
    {
        m_pDealThread = new MyDealThread(m_FilePath, this);
    }
    m_pDealThread->start();

    //启动抓包线程
    m_pPcapThread = new PcapThread(m_pAHandle, p_Port, this);
    m_pPcapThread->start();
}


/**
 * @brief PcapCommon::sendData  发送数据包
 */
void PcapCommon::sendData(QByteArray srcIp,QByteArray dstIp,QByteArray data,unsigned short srcPort,unsigned short dstPort)
{
    char * t_buffer = { 0 };
    t_buffer = (char*)malloc(SIZE_ETHERNET+sizeof(sniff_ip)+sizeof(sniff_tcp)+data.length());
    memset(t_buffer, 0, SIZE_ETHERNET+sizeof(sniff_ip)+sizeof(sniff_tcp)+data.length());

    sniff_ethernet *t_ethernet = (sniff_ethernet*)t_buffer;
    sniff_ip *t_ip_header = (sniff_ip*)(t_buffer+SIZE_ETHERNET);
    sniff_tcp *t_tcp_header = (sniff_tcp*)(t_buffer+SIZE_ETHERNET+sizeof(sniff_ip));

    //MAC地址
    memset(t_ethernet,1,12);
    t_ethernet->ether_type = htons(0x0800);

    //设置IP头
    t_ip_header->ip_vhl = 0x45;
//    t_ip_header->ip_vhl = IP_V(4);
    t_ip_header->ip_tos = 0;
    t_ip_header->ip_len = htons(54+data.length()-SIZE_ETHERNET); //12288
    t_ip_header->ip_id = 616;                //616
    t_ip_header->ip_off = 64;
    t_ip_header->ip_ttl = 128;
    t_ip_header->ip_p = IPPROTO_TCP;
    t_ip_header->ip_sum = 0;
    t_ip_header->ip_src.S_un.S_addr = inet_addr(srcIp.constData());
    t_ip_header->ip_dst.S_un.S_addr = inet_addr(dstIp.constData());
    t_ip_header->ip_sum = in_cksum((u_int16_t*)t_ip_header, sizeof(sniff_ip));

    //设置TCP头
    t_tcp_header->th_sport = htons(srcPort);
    t_tcp_header->th_dport = htons(dstPort);
    t_tcp_header->th_seq = htonl(1);
    t_tcp_header->th_ack = htonl(1);
    t_tcp_header->th_offx2 = sizeof(sniff_tcp) / 4;
    t_tcp_header->th_flags = 0x40;
    t_tcp_header->th_win = 65535;
    t_tcp_header->th_sum = 0;
    t_tcp_header->th_urp = 0;
    t_tcp_header->th_sum = in_cksum((u_int16_t*)t_tcp_header, sizeof(sniff_tcp));

    memcpy(t_buffer+SIZE_ETHERNET+sizeof(sniff_ip)+sizeof(sniff_tcp),
           data.data(),
           SIZE_ETHERNET+sizeof(sniff_ip)+sizeof(sniff_tcp)+data.length());

    //构建UDP数据头;
//    pudp_herder->dest = htons(7865); //目的端口号
//    pudp_herder->source = htons(2834);//源端口号
//    pudp_herder->len = htons(sizeof(buffer) – sizeof(ether_header) – sizeof(ip_header));//设定长度
//    pudp_herder->checkl = 0;//设定检验和

//    //构造伪UDP首部
//    char buffer2[64] = { 0 };
//    Psd_Header* psd = (Psd_Header*)buffer2;
//    psd->sourceip = inet_addr(“192.168.18.*”);
//    psd->destip = inet_addr(“122.*.*.*”);
//    psd->ptcl = IPPROTO_UDP;
//    psd->plen = htons(sizeof(buffer) – sizeof(ether_header) – sizeof(ip_header));
//    psd->mbz = 0;
//    memcpy(buffer2 + sizeof(Psd_Header), (void*)pudp_herder, sizeof(buffer) – sizeof(ether_header) – sizeof(ip_header));

//    pudp_herder->checkl = in_cksum((u_int16_t *)buffer2,sizeof(buffer) – sizeof(ether_header) – sizeof(ip_header) + sizeof(Psd_Header));

    if (-1 == pcap_sendpacket(m_pAHandle,
                             (const u_char*)t_buffer,
                             SIZE_ETHERNET+sizeof(sniff_ip)+sizeof(sniff_tcp)+data.length()))
    {
        qDebug()<<"send error";
    }

    t_buffer = NULL;
    free(t_buffer);
}

/**
 * @brief PcapCommon::closeCard  关闭pcap并结束抓包进程，保存文件
 */
void PcapCommon::closeCard()
{
    if (m_pAHandle)
    {
        pcap_close(m_pAHandle);
        m_pAHandle = NULL;
    }

    if (m_pDealThread)
    {
        m_pDealThread->stopCapturing();
    }

    if(m_pPcapThread)
    {
        if (m_pPcapThread->isRunning())
            m_pPcapThread->wait();
        delete m_pPcapThread;
        m_pPcapThread = NULL;
    }

    if (m_pDevs)
	{
        delete m_pDevs;
		m_pDevs = NULL;
	}
}


/**
 * @brief PcapCommon::setPort  设置端口过滤
 * @param port  过滤端口
 */
void PcapCommon::setPort(unsigned short port)
{
    p_Port = port;
}


/**
 * @brief PcapCommon::setFilePath   设置存放文件路径
 * @param path  最后一次抓包保存文件的路径
 */
void PcapCommon::setFilePath(QString path)
{
    //为设置路径添加文件名称
    m_CurrentFileName = getTime()+".dat";
    m_FilePath+=path+"/"+m_CurrentFileName;
}


/**
 * @brief PcapCommon::getFileName  获取本次保存的文件名称
 * @return   最后一次抓包结束保存文件的文件名
 */
QString PcapCommon::getFileName()
{
    return m_CurrentFileName;
}


/**
 * @brief PcapCommon::getPcap_t 获取pcap指针
 * @return
 */
pcap_t* PcapCommon::getPcap_t()
{
    return m_pAHandle;
}


/**
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


/**
 * @brief PcapCommon::ifPcap_t  打印该适配器所有可用的信息
 * @param d  适配器信息指针
 * @return   适配器信息
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

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short PcapCommon::in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    unsigned short *w = addr;
    unsigned short answer;
    int sum = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum),
     * we add sequential 16 bit words to it, and at the end, fold
     * back all the carry bits from the top 16 bits into the lower
     * 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += *(unsigned char *)w;

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return (answer);
}

/**
 * @brief check_sum 计算UDP校验和
 * @param a
 * @param len
 * @return
 */
unsigned short PcapCommon::check_UDP_sum(unsigned short *a, int len)
{
    unsigned int sum = 0;

    while (len > 1) {
        sum += *a++;
        len -= 2;
    }

    if (len) {
        sum += *(unsigned char *)a;
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return (unsigned short)(~sum);
}



#define IPTOSBUFFERS    12
/**
 * @brief PcapCommon::iptos  将数字类型的IP地址转换成字符串类型的
 * @param in  IP
 * @return    转换后IP信息
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


/**
 * @brief PcapCommon::ip6tos
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


/**
 * @brief PcapCommon::getTime  获取当前时间
 * @return  年月日-时分秒
 */
QString PcapCommon::getTime()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh.mm.ss");
}




















