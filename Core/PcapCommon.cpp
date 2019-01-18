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
    /* �ͷ� */
    pcap_freealldevs(alldevs);
}

void PcapCommon::Reset()
{
    p_Port = 0;
}


void PcapCommon::winSocketInit()
{
    WSADATA wsaData;
    // ����Windows Sockets DLL
    if (WSAStartup(MAKEWORD(2, 1), &wsaData)) {
        qDebug() << "Winsock�޷���ʼ��!";
        WSACleanup();
        return;
    }
}

//ɨ�貢���ر����豸�б�
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

        //��������������ϸ��Ϣ
        pcap_addr_t *a;     //TODO:ָ�������ʼ��
        for (a = alldevs->addresses; a; a = a->next) {
            switch (a->addr->sa_family)
            {
                case AF_INET:
                    {
                    t_Dev.familyName = "AF_INET";
                    //IP
                    if (a->addr)
                        t_Dev.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                    //����
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

//�������̿�ʼ��������
bool PcapCommon::openCard(const _DEVInfo DevInfo)
{
    //ѡ����ץ���ļ�·��
    QWidget *t_filePathWidget = new QWidget;
    QString file_path = QFileDialog::getExistingDirectory(t_filePathWidget, "��ѡ�񱣴�·��...", "./");
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
    //���ļ�
    file_path += "/" + getTime() + ".dat";
    writeFile = new QFile(file_path);
    if (!writeFile->open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return false;

    //
    char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���
    //��������
    if ((adHandle = pcap_open_live(
             DevInfo.name.toUtf8().data(),	//�豸��
             65535,		//Ҫ��׽�����ݰ��Ĳ���	65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
             PCAP_OPENFLAG_PROMISCUOUS,	//���û���ģʽ
             1000,		//��ȡ��ʱʱ��
             errbuf		//���󻺳��
             )) == NULL)
    {
        qDebug() << stderr << QString("Unable to open the adapter. [%1] is not supported by WinPcap").arg(devs->name);
        pcap_freealldevs(alldevs);
        return false;
    }

    //��������Ϊ���߾�����
    //if (pcap_datalink(adHandle) == DLT_IEEE802) {
    //	printf("DLT_IEEE802");
    //}
    /* ���������·�㣬ֻ������̫�� */
    //if (pcap_datalink(adHandle) != DLT_EN10MB)
    //{
    //	qDebug()<<"This program works only on Ethernet networks.";
    //	/* �ͷ��豸�б� */
    //	pcap_freealldevs(alldevs);
    //	return false;
    //}

    //���ù�����
    if (!setFilter(DevInfo.netmask.toUtf8().data(), (char*)"ip"))
    {
        return false;
    }

    //�����߳̽���ץ��
    pcapThread = new PcapThread(adHandle, p_Port);
    qRegisterMetaType<_MessageContent>("_MessageContent");		//ע��_MessageContent
    connect(pcapThread, SIGNAL(signal_Data(_MessageContent, QByteArray)),
            this, SLOT(slot_RecvDataInfo(_MessageContent, QByteArray)) );
    pcapThread->start();
    return true;
}

//�ر�pcap������ץ�����̣������ļ�
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

//���ö˿ڹ���
void PcapCommon::SetPort(u_short port)
{
    p_Port = port;
}

//���յ���Ϣ����¼����ð�����
void PcapCommon::slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload)
{
    QDataStream out(writeFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_mac((char*)MsgCon.SrcMACAddress, 6);
    QByteArray dst_mac((char*)MsgCon.DstMACAddress, 6);
    QByteArray src_ip = inet_ntoa(MsgCon.SrcAddress);
    QByteArray dst_ip = inet_ntoa(MsgCon.DstAddress);	//�շ�IPת��

    //��ʽ��QByteArray*4��u_short*2��double��QByteArray
    out << src_mac.data() << dst_mac.data() << src_ip.data() << dst_ip.data()
        << MsgCon.SrcPoet << MsgCon.DstPoet << MsgCon.TimeDifference << payload.data();

    qDebug() << QString("%1  %2  %3  %4  %5  %6  %7  %8")
                .arg(src_mac.toHex().data()).arg(dst_mac.toHex().data()).arg(src_ip.data()).arg(dst_ip.data())
                .arg(MsgCon.SrcPoet).arg(MsgCon.DstPoet).arg(MsgCon.TimeDifference).arg(payload.data());
}

//��ȡ������ļ�
void PcapCommon::readDatFile()
{
    //ѡ����ץ���ļ�·��
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
        u_short DstPoet;			//�շ�Port
        double TimeDifference;		//����ʱ��

        out >> src_mac >> dst_mac >> src_ip >> dst_ip >> SrcPoet >> DstPoet >> TimeDifference << payload;

        qDebug() << QString("%1  %2  %3  %4  %5  %6  %7  %8")
                    .arg(src_mac.toHex().data()).arg(dst_mac.toHex().data()).arg(src_ip.data()).arg(dst_ip.data())
                    .arg(SrcPoet).arg(DstPoet).arg(TimeDifference).arg(payload.data());
    }

    file.close();
}

/*
����˵����
    ���ù�����

������Ϣ��
    const char *netmask		//����
    char* packet_filter		//��������

����ֵ��
    BOOL	true:���óɹ�	false:����ʧ��
*/
bool PcapCommon::setFilter(const char* netmask, char* packet_filter)
{
    u_int ui_netmask = QString(netmask).toInt();
    struct bpf_program fcode;
    //���������
    if (pcap_compile(adHandle, &fcode, packet_filter, 1, ui_netmask) < 0)
    {
        qDebug() << stderr, "Unable to compile thepacket filter. Check the syntax.";
        pcap_freealldevs(alldevs);
        return false;
    }

    //���ù�����
    if (pcap_setfilter(adHandle, &fcode) < 0)
    {
        qDebug() << "Error setting thefilter";
        pcap_freealldevs(alldevs);
        return false;
    }
    return true;
}

/**
 * ˵��: ��ӡ���������п��õ���Ϣ
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

    /* �ػ���ַ */
    qDebug() << QString("%1").arg((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    /* IP addresses */
    for (a = d->addresses; a; a = a->next) {
        qDebug() << QString("Address Family: #%1").arg(a->addr->sa_family);

        /*���� sockaddr_in �ṹ��ο���������������*/
        switch (a->addr->sa_family)
        {
            case AF_INET:
                qDebug() << QString("\t --------------Address Family Name: AF_INET--------------\n");//��ӡ�����ַ����
                if (a->addr)		//��ӡIP��ַ
                    qDebug() << QString("\t Address: %1\n").arg(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                if (a->netmask)		//��ӡ����
                    qDebug() << QString("\t Netmask: %1\n").arg(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)	//��ӡ�㲥��ַ
                    qDebug() << QString("\tBroadcast Address: %1 \n").arg(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)		//Ŀ�ĵ�ַ
                    qDebug() << QString("\t Destination Address: %1 \n").arg(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                break;
            default:
                qDebug() << QString("\t Address Family Name: Unknown \n");
                break;
        }
    }
    qDebug() << "\n";
}

/* ���������͵�IP��ַת�����ַ������͵� */
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
*	��ȡ��ǰʱ��
*/
QString PcapCommon::getTime()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh.mm.ss");
}
