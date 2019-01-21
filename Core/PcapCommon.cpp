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
    reset();
}

PcapCommon::PcapCommon(unsigned short port)
{
    p_Port = port;
}


PcapCommon::~PcapCommon()
{
    reset();

    pcap_freealldevs(m_pAlldevs);
}

void PcapCommon::reset()
{
    p_Port = 0;
}

/**
 * @brief PcapCommon::winSocketInit ��ʼ��Winsock
 * @param NULL
 * @return void
 */
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


/**
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

    _DEVInfo t_Dev;
    QVector<_DEVInfo> Decs;

    for (m_pDevs = m_pAlldevs; m_pDevs; m_pDevs = m_pDevs->next)
    {
        //pcap_t *handle;
        //if ((handle = pcap_open_live(m_pDevs->name,65535,PCAP_OPENFLAG_PROMISCUOUS,1000,errbuf)) == NULL)
        //{
        //	qDebug() << stderr << QString("Unable to open the adapter. [%1] is not supported by WinPcap").arg(m_pDevs->name);
        //	pcap_freealldevs(m_pAlldevs);
        //}

        ///* ���������·�㣬ֻ������̫�� */
        //if (pcap_datalink(handle) == DLT_IEEE802)	//���߾�����
        //{
        //	t_Dev.description = QString::fromLocal8Bit("WLAN");
        //}
        //else if (pcap_datalink(handle) == DLT_EN10MB)	//��̫��
        //{
        //	t_Dev.description = QString::fromLocal8Bit("��̫��");
        //}
        //else
        //{
        //	return Decs;
        //}
        //pcap_close(handle);
        //delete handle;
        //handle = NULL;

        t_Dev.name = m_pDevs->name;
        t_Dev.description = m_pDevs->description;


        //��������������ϸ��Ϣ
        pcap_addr_t *a;
        for (a = m_pAlldevs->addresses; a; a = a->next)
        {
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
            }
                break;
            case AF_INET6:
                //if (a->addr)
                //{
                //	qDebug() << "Address Family Name:AF_INET6";
                //	qDebug() << "this is an IPV6 address";
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


/**
 * @brief PcapCommon::openCard �������̿�ʼ��������
 * @param const _DEVInfo DevInfo
 * @return bool �Ƿ���������ץ������
 */
bool PcapCommon::openCard(const _DEVInfo DevInfo)
{
    char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���
    //��������
    if ((m_pAHandle = pcap_open_live(
             DevInfo.name.toUtf8().data(),	//�豸��
             65535,		//Ҫ��׽�����ݰ��Ĳ���	65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
             PCAP_OPENFLAG_PROMISCUOUS,	//���û���ģʽ
             1000,		//��ȡ��ʱʱ��
             errbuf		//���󻺳��
             )) == NULL)
    {
        qDebug() << stderr << QString("Unable to open the adapter. [%1] is not supported by WinPcap").arg(m_pDevs->name);
        pcap_freealldevs(m_pAlldevs);
        return false;
    }

    //���ù�������
    QByteArray tFilter("ip and port ");
    tFilter.append(QString("%1").arg(p_Port));
    //���ù�����
    if (!setFilter(DevInfo.netmask.toUtf8().data(), tFilter.data()))
    {
        return false;
    }

    //�����߳̽���ץ��
    m_pPcapThread = new PcapThread(m_pAHandle, p_Port);
    qRegisterMetaType<_MessageContent>("_MessageContent");		//ע��_MessageContent
    connect(m_pPcapThread, SIGNAL(signal_Data(_MessageContent, QByteArray)),
            this, SLOT(slot_RecvDataInfo(_MessageContent, QByteArray)) );
    m_pPcapThread->start();
    return true;
}

/**
 * @brief PcapCommon::closeCard �ر�pcap������ץ�����̣������ļ�
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
    m_pPcapThread->wait();

    if (m_pWriteFile->isOpen())
    {
        m_pWriteFile->close();
    }
}

/**
 * @brief PcapCommon::SetPort ���ö˿ڹ���
 * @param unsigned short port
 * @return void
 */
void PcapCommon::setPort(unsigned short port)
{
    p_Port = port;
}

/**
 * @brief PcapCommon::setFilePath   ���ô���ļ�·��
 * @param path
 */
void PcapCommon::setFilePath(QString path)
{
    //Ϊ����·������ļ�����
    path+="/"+getTime()+".dat";
    m_pWriteFile = new QFile(path);
    if (!m_pWriteFile->open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return;
}

/**
 * @brief PcapCommon::slot_RecvDataInfo  ���յ���Ϣ����¼����ð�����
 * @param MsgCon    ����ͷ��Ϣ
 * @param payload   ������������
 */
void PcapCommon::slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload)
{
    QDataStream out(m_pWriteFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_mac((char*)MsgCon.SrcMACAddress, 6);
    QByteArray dst_mac((char*)MsgCon.DstMACAddress, 6);
    QByteArray src_ip = inet_ntoa(MsgCon.SrcAddress);
    QByteArray dst_ip = inet_ntoa(MsgCon.DstAddress);	//�շ�IPת��

    //��ʽ��QByteArray*4��unsigned short*2��double��QByteArray
    out << src_mac.data() << dst_mac.data() << src_ip.data() << dst_ip.data()
        << MsgCon.SrcPoet << MsgCon.DstPoet << MsgCon.TimeDifference << payload.data();

    qDebug() << QString("%1  %2  %3  %4  %5  %6  %7  %8")
                .arg(src_mac.toHex().data()).arg(dst_mac.toHex().data()).arg(src_ip.data()).arg(dst_ip.data())
                .arg(MsgCon.SrcPoet).arg(MsgCon.DstPoet).arg(MsgCon.TimeDifference).arg(payload.toHex().data());
}

/**
 * @brief PcapCommon::readDatFile ��ȡ������ļ�
 */
void PcapCommon::readDatFile(QString path)
{
    QFile file(path);
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

        unsigned short SrcPoet;
        unsigned short DstPoet;		//�շ�Port
        double TimeDifference;		//����ʱ��

        out >> src_mac >> dst_mac >> src_ip >> dst_ip
            >> SrcPoet >> DstPoet >> TimeDifference >> payload;

        qDebug() << QString("%1  %2  %3  %4  %5  %6  %7  %8")
                    .arg(src_mac.toHex().data()).arg(dst_mac.toHex().data()).arg(src_ip.data()).arg(dst_ip.data())
                    .arg(SrcPoet).arg(DstPoet).arg(TimeDifference).arg(payload.toHex().data());
    }

    file.close();
}


/**
 * @brief PcapCommon::setFilter   ���ù�����
 * @param const char *netmask     ����
 * @param char* packet_filter     ��������
 * @return bool true:���óɹ� false:����ʧ��
 */
bool PcapCommon::setFilter(const char* netmask, char* packet_filter)
{
    unsigned int ui_netmask = QString(netmask).toInt();
    struct bpf_program fcode;
    //���������
    if (pcap_compile(m_pAHandle, &fcode, packet_filter, 1, ui_netmask) < 0)
    {
        qDebug() << stderr, "Unable to compile thepacket filter. Check the syntax.";
        pcap_freealldevs(m_pAlldevs);
        return false;
    }

    //���ù�����
    if (pcap_setfilter(m_pAHandle, &fcode) < 0)
    {
        qDebug() << "Error setting thefilter";
        pcap_freealldevs(m_pAlldevs);
        return false;
    }
    return true;
}


/**
 * @brief PcapCommon::ifPcap_t  ��ӡ�����������п��õ���Ϣ
 * @param d
 */
void PcapCommon::ifPcap_t(pcap_if_t *d)
{
    pcap_addr_t *a;

    qDebug() << d->name;

    if (d->description)
        qDebug() << "Description" << d->description;

    //�ػ���ַ
    qDebug() << QString("%1").arg((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    //IP addresses
    for (a = d->addresses; a; a = a->next) {
        qDebug() << QString("Address Family: #%1").arg(a->addr->sa_family);

        //���� sockaddr_in �ṹ��ο���������������
        switch (a->addr->sa_family)
        {
        case AF_INET:
            qDebug() << QString("--------------Address Family Name: AF_INET--------------");  //��ӡ�����ַ����
            if (a->addr)		//��ӡIP��ַ
                qDebug() << QString("Address: %1").arg(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            if (a->netmask)		//��ӡ����
                qDebug() << QString("Netmask: %1").arg(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)	//��ӡ�㲥��ַ
                qDebug() << QString("\tBroadcast Address: %1 ").arg(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)		//Ŀ�ĵ�ַ
                qDebug() << QString("Destination Address: %1 ").arg(iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            break;
        default:
            qDebug() << QString("Address Family Name: Unknown ");
            break;
        }
    }
}

#define IPTOSBUFFERS    12

/**
 * @brief PcapCommon::iptos  ���������͵�IP��ַת�����ַ������͵�
 * @param in  IP
 * @return    ת����IP
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
 * @brief PcapCommon::getTime   ��ȡ��ǰʱ��
 * @return  ������-ʱ����
 */
QString PcapCommon::getTime()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh.mm.ss");
}




















