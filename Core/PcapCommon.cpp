#include "PcapCommon.h"

#include <QDebug>
#include <QThread>
#include <QObject>
#include <QFileDialog>
#include <QApplication>
#include <QWidget>
#include <QDateTime>

#include <windows.h>
#include <winsock.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "packet.lib")


PcapCommon::PcapCommon()
{
    Reset();
}

PcapCommon::PcapCommon(u_short port)
{
    p_Port = port;
}


PcapCommon::~PcapCommon()
{
    Reset();
    /* 释放 */
    pcap_freealldevs(alldevs);
}

void PcapCommon::Reset()
{
    p_Port = 0;
}


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

//扫描并返回本机设备列表
QVector<_DEVInfo> PcapCommon::findAllDev()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << errbuf;
        pcap_freealldevs(alldevs);
        exit(1);
    }

    decCount = 0;
    _DEVInfo t_Dev;
    QVector<_DEVInfo> Decs;

    for (devs = alldevs; devs; devs = devs->next)
    {
        qDebug() << ++decCount << devs->name << "\tDescription:" << devs->description;

        t_Dev.name = devs->name;
        if (devs->description)
        {
            t_Dev.description = devs->description;
        }
        else
        {
            t_Dev.description = "No description available";
        }

        if (0 == decCount)
        {
            qDebug("No interfaces found! Make sure WinPcap is installed.");
            return Decs;
        }

        //遍历适配器的详细信息
        pcap_addr_t *a;     //TODO:指针变量初始化
        for (a = alldevs->addresses; a; a = a->next) {
            switch (a->addr->sa_family)
            {
                case AF_INET:
                    {
                    t_Dev.familyName = "AF_INET";
                    //IP
                    if (a->addr)
                        t_Dev.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                    //网段
                    if (a->netmask)
                        t_Dev.netmask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                    //if (a->broadaddr)
                    //	qDebug() << QString("Broadcast Address: %1\n").arg(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                    //if (a->dstaddr)
                    //	qDebug() << QString("\tDestination Address: %1").arg(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                    }
                    break;
                case AF_INET6:
                    //if (a->addr)
                    //{
                    //	qDebug() << "Address Family Name:AF_INET6\n";
                    //	qDebug() << "this is an IPV6 address\n";
                    //}
                    break;
                default:
                    break;
            }
        }
        Decs.append(t_Dev);
    }

    return Decs;
}

//开启进程开始捕获数据
bool PcapCommon::openCard(const _DEVInfo DevInfo)
{
    //选择存放抓包文件路径
    QWidget *t_filePathWidget = new QWidget;
    QString file_path = QFileDialog::getExistingDirectory(t_filePathWidget, "请选择保存路径...", "./");
    if (file_path.isEmpty())
    {
        delete t_filePathWidget;
        t_filePathWidget = NULL;
        return false;
    }
    else
    {
        delete t_filePathWidget;
        t_filePathWidget = NULL;
    }
    //打开文件
    file_path += "/" + getTime() + ".dat";
    writeFile = new QFile(file_path);
    if (!writeFile->open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return false;

    //
    char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区
    //打开适配器
    if ((adHandle = pcap_open_live(
             DevInfo.name.toUtf8().data(),	//设备名
             65535,		//要捕捉的数据包的部分	65535保证能捕获到不同数据链路层上的每个数据包的全部内容
             PCAP_OPENFLAG_PROMISCUOUS,	//设置混杂模式
             1000,		//读取超时时间
             errbuf		//错误缓冲池
             )) == NULL)
    {
        qDebug() << stderr << QString("Unable to open the adapter. [%1] is not supported by WinPcap").arg(devs->name);
        pcap_freealldevs(alldevs);
        return false;
    }

    //所在网络为无线局域网
    //if (pcap_datalink(adHandle) == DLT_IEEE802) {
    //	printf("DLT_IEEE802");
    //}
    /* 检查数据链路层，只考虑以太网 */
    //if (pcap_datalink(adHandle) != DLT_EN10MB)
    //{
    //	qDebug()<<"This program works only on Ethernet networks.";
    //	/* 释放设备列表 */
    //	pcap_freealldevs(alldevs);
    //	return false;
    //}

    //设置过滤器
    if (!setFilter(DevInfo.netmask.toUtf8().data(), (char*)"ip"))
    {
        return false;
    }

    //启动线程进行抓包
    pcapThread = new PcapThread(adHandle, p_Port);
    qRegisterMetaType<_MessageContent>("_MessageContent");		//注册_MessageContent
    connect(pcapThread, SIGNAL(signal_Data(_MessageContent, QByteArray)),
            this, SLOT(slot_RecvDataInfo(_MessageContent, QByteArray)) );
    pcapThread->start();
    return true;
}

//关闭pcap并结束抓包进程，保存文件
void PcapCommon::closeCard()
{
    if (adHandle != NULL)
    {
        pcap_close(adHandle);
        adHandle = NULL;
    }
    pcapThread->wait();

    if (writeFile->isOpen())
    {
        writeFile->close();
    }
}

//设置端口过滤
void PcapCommon::SetPort(u_short port)
{
    p_Port = port;
}

//接收到消息，记录保存该包数据
void PcapCommon::slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload)
{
    QDataStream out(writeFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_mac((char*)MsgCon.SrcMACAddress, 6);
    QByteArray dst_mac((char*)MsgCon.DstMACAddress, 6);
    QByteArray src_ip = inet_ntoa(MsgCon.SrcAddress);
    QByteArray dst_ip = inet_ntoa(MsgCon.DstAddress);	//收发IP转换

    //格式：QByteArray*4、u_short*2、double、QByteArray
    out << src_mac.data() << dst_mac.data() << src_ip.data() << dst_ip.data()
        << MsgCon.SrcPoet << MsgCon.DstPoet << MsgCon.TimeDifference << payload.data();

    qDebug() << QString("%1  %2  %3  %4  %5  %6  %7  %8")
                .arg(src_mac.toHex().data()).arg(dst_mac.toHex().data()).arg(src_ip.data()).arg(dst_ip.data())
                .arg(MsgCon.SrcPoet).arg(MsgCon.DstPoet).arg(MsgCon.TimeDifference).arg(payload.data());
}

//读取保存的文件
void PcapCommon::readDatFile()
{
    //选择存放抓包文件路径
    QWidget *t_filePathWidget = new QWidget;

    QString file_path = QFileDialog::getOpenFileName(t_filePathWidget, tr("select file"), "./", "*.dat");
    if (file_path.isEmpty())
    {
        delete t_filePathWidget;
        t_filePathWidget = NULL;
        return;
    }
    else
    {
        delete t_filePathWidget;
        t_filePathWidget = NULL;
    }
    QFile file(file_path);
    if (!file.open(QIODevice::ReadOnly))
        return;
    QDataStream out(&file);

    while (!out.atEnd())
    {
        QByteArray src_mac;
        QByteArray dst_mac;
        QByteArray src_ip;
        QByteArray dst_ip;
        QByteArray payload;

        u_short SrcPoet;
        u_short DstPoet;			//收发Port
        double TimeDifference;		//报文时差

        out >> src_mac >> dst_mac >> src_ip >> dst_ip >> SrcPoet >> DstPoet >> TimeDifference << payload;

        qDebug() << QString("%1  %2  %3  %4  %5  %6  %7  %8")
                    .arg(src_mac.toHex().data()).arg(dst_mac.toHex().data()).arg(src_ip.data()).arg(dst_ip.data())
                    .arg(SrcPoet).arg(DstPoet).arg(TimeDifference).arg(payload.data());
    }

    file.close();
}

/*
方法说明：
    设置过滤器

参数信息：
    const char *netmask		//掩码
    char* packet_filter		//过滤条件

返回值：
    BOOL	true:设置成功	false:设置失败
*/
bool PcapCommon::setFilter(const char* netmask, char* packet_filter)
{
    u_int ui_netmask = QString(netmask).toInt();
    struct bpf_program fcode;
    //编译过滤器
    if (pcap_compile(adHandle, &fcode, packet_filter, 1, ui_netmask) < 0)
    {
        qDebug() << stderr, "Unable to compile thepacket filter. Check the syntax.";
        pcap_freealldevs(alldevs);
        return false;
    }

    //设置过滤器
    if (pcap_setfilter(adHandle, &fcode) < 0)
    {
        qDebug() << "Error setting thefilter";
        pcap_freealldevs(alldevs);
        return false;
    }
    return true;
}

/**
 * 说明: 打印对象中所有可用的信息
 */
void PcapCommon::ifPcap_t(pcap_if_t *d)
{
    pcap_addr_t *a;

    qDebug() << "start printf";

    /* Name */
    qDebug() << d->name;

    /* Description */
    if (d->description)
        qDebug() << "Description" << d->description;

    /* 回环地址 */
    qDebug() << QString("%1").arg((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    /* IP addresses */
    for (a = d->addresses; a; a = a->next) {
        qDebug() << QString("Address Family: #%1").arg(a->addr->sa_family);

        /*关于 sockaddr_in 结构请参考其他的网络编程书*/
        switch (a->addr->sa_family)
        {
            case AF_INET:
                qDebug() << QString("\t --------------Address Family Name: AF_INET--------------\n");//打印网络地址类型
                if (a->addr)		//打印IP地址
                    qDebug() << QString("\t Address: %1\n").arg(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                if (a->netmask)		//打印掩码
                    qDebug() << QString("\t Netmask: %1\n").arg(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)	//打印广播地址
                    qDebug() << QString("\tBroadcast Address: %1 \n").arg(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)		//目的地址
                    qDebug() << QString("\t Destination Address: %1 \n").arg(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                break;
            default:
                qDebug() << QString("\t Address Family Name: Unknown \n");
                break;
        }
    }
    qDebug() << "\n";
}

/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char* PcapCommon::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/*!
*	获取当前时间
*/
QString PcapCommon::getTime()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh.mm.ss");
}
