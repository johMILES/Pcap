#include "PcapCommon.h"

#include <QDebug>
#include <QThread>
#include <QObject>
#include <QFileDialog>
#include <QApplication>
#include <QWidget>
#include <QDateTime>
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

    QList<_LocalCardInfo> cardList;
    QList<QNetworkInterface> list = QNetworkInterface::allInterfaces();
    foreach (QNetworkInterface netInterface, list)
    {
        if (!netInterface.isValid())
            continue;

        _LocalCardInfo card;
        card.humanReadableName = netInterface.humanReadableName();  //�ɶ�������

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

    //�Ա����λ�ȡ������IP�Ƿ���ͬ ��ͬ���滻����������
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
	connect(m_pPcapThread, SIGNAL(signal_PayloadData(_MessageContent, QByteArray)),
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
 * @param path  ���һ��ץ�������ļ���·��
 */
void PcapCommon::setFilePath(QString path)
{
    //Ϊ����·������ļ�����
    m_CurrentFileName = getTime()+".dat";
    m_FilePath+=path+"/"+m_CurrentFileName;
    m_pWriteFile = new QFile(m_FilePath);
	if (!m_pWriteFile->open(QIODevice::WriteOnly/* | QIODevice::Truncate | QIODevice::Text*/))
		return;

}


/**
 * @brief PcapCommon::getFileName  ��ȡ���α�����ļ�����
 * @return  ���һ��ץ�����������ļ����ļ���
 */
QString PcapCommon::getFileName()
{
    return m_CurrentFileName;
}


/**
 * @brief PcapCommon::slot_RecvDataInfo  ���յ���Ϣ����¼����ð�����
 * @param MsgCon    ����ͷ��Ϣ
 * @param payload   ������������
 */
void PcapCommon::slot_RecvDataInfo(_MessageContent MsgCon, QByteArray payload)
{
	static double time = 0;
	static bool flag = false;
	if (flag)
	{
		flag = false;
		if (!m_pWriteFile->open(QIODevice::Append))
			return;
	}

    QDataStream out(m_pWriteFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_ip = inet_ntoa(MsgCon.SrcAddress);
    QByteArray dst_ip = inet_ntoa(MsgCon.DstAddress);	//�շ�IPת��

    out << src_ip.data() << dst_ip.data()
        << MsgCon.SrcPoet << MsgCon.DstPoet
		<< QByteArray::number(MsgCon.TimeDifference, 'E') << payload.toHex().data();

	time += MsgCon.TimeDifference;
	if (time > 1)
	{
		time = 0;
		flag = true;
		m_pWriteFile->close();
	}
	//    qDebug() << QString("%1  %2  %3  %4  %5  %6 ")
	//                /*.arg(src_mac.toHex().data()).arg(dst_mac.toHex().data())*/.arg(src_ip.data()).arg(dst_ip.data())
	//                .arg(MsgCon.SrcPoet).arg(MsgCon.DstPoet).arg(MsgCon.TimeDifference).arg(payload.toHex().data());
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
        QByteArray src_ip;
        QByteArray dst_ip;
        QByteArray payload;

		ushort SrcPoet;
		ushort DstPoet;		//�շ�Port
		QByteArray TimeDifference;		//����ʱ��

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

    //�ػ���ַ
//    qDebug() << QString("%1").arg((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    for (a = d->addresses; a; a = a->next) {
//        qDebug() << QString("Address Family: #%1").arg(a->addr->sa_family);

        switch (a->addr->sa_family)
        {
        case AF_INET:
            Dev.familyName = "AF_INET";
//            qDebug() << QString("--------------AF_INET--------------");  //��ӡ�����ַ����
            if (a->addr)		//��ӡIP��ַ
            {
                Dev.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
//                qDebug() << QString("Address: %1").arg(iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            }
            if (a->netmask)		//��ӡ����
            {
                Dev.netmask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
//                qDebug() << QString("Netmask: %1").arg(iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            }
//            if (a->broadaddr)	//��ӡ�㲥��ַ
//                qDebug() << QString("\tBroadcast Address: %1 ").arg(iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
//            if (a->dstaddr)		//Ŀ�ĵ�ַ
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


/**
 * @brief PcapCommon::getTime   ��ȡ��ǰʱ��
 * @return  ������-ʱ����
 */
QString PcapCommon::getTime()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh.mm.ss");
}




















