#include "PcapThread.h"
#include "gloab.h"


#include <QDebug>
#include <QApplication>


PcapThread *p_PcapThread = NULL;

PcapThread::PcapThread(pcap_t *dev, unsigned short port, QObject *object)
	: QThread(object)
{
	m_pDev = dev;
	p_Port = port;

    p_PcapThread = this;
}


PcapThread::~PcapThread()
{
}


/**
 * @brief pcapLoop  捕获功能(pcap_loop)的回调函数
 * @param param
 * @param header    通用包信息
 * @param pkt_data  报文数据信息
 */
void pcapLoop(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
void pcapLoop(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
    p_PcapThread->parsingDataPackets(header, pkt_data);
}


/**
 * @brief PcapThread::run  线程运行
 */
void PcapThread::run()
{
    //利用pcap_next_ex来接受数据包
    int res;	//表示是否接收到了数据包
    struct pcap_pkthdr *header;		//接收到的数据包的头部
    const unsigned char *pkt_data;	//接收到的数据包的内容

    while ((res = pcap_next_ex(m_pDev, &header, &pkt_data)) >= 0)
    {
        if (res == 0) {
            //返回值为0代表接受数据包超时，重新循环继续接收
            continue;
        }
        else
        {
            p_PcapThread->parsingDataPackets(header, pkt_data);
        }
    }

    //利用回调捕获数据包，每捕获一帧数据触发pcapLoop一次
    //pcap_loop(Dev, 0, pcapLoop, NULL);
}


/**
 * @brief PcapThread::parsingDataPackets  解析捕获到的数据包功能
 * @param header    数据包通用信息
 * @param pkt_data  该数据包全部信息
 * @note pkt_data   指向的数据包结构：  以太网首部[14] + IP包首部[20] + TCP包首部[20] + 正文内容[...]
 */
void PcapThread::parsingDataPackets(const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
    const struct sniff_ethernet *t_Ethernet;  // 以太网头
    const struct sniff_ip *t_IP;              // IP头
    int t_IPLength;

    // 计算以太网头信息
    t_Ethernet = (struct sniff_ethernet*)(pkt_data);

    // 定义/计算IP头偏移量
    t_IP = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
    t_IPLength = IP_HL(t_IP) * 4;
    if (t_IPLength < 20) {
        //qDebug() << QString("   * Invalid IP header length: %1 bytes").arg(t_IPLength);
        return;
    }

    MessageContent t_MsgCon;
    t_MsgCon.SrcAddress = t_IP->ip_src;
    t_MsgCon.DstAddress = t_IP->ip_dst;		//转换：inet_ntoa

    //保留_收发MAC地址
    //memcpy(&t_MsgCon.DstMACAddress, t_Ethernet, 6);
    //memcpy(&t_MsgCon.SrcMACAddress, t_Ethernet+6, 6);

    switch (t_IP->ip_p)		//确定协议
    {
    case IPPROTO_TCP:
        TCP(t_MsgCon, t_IPLength, header->len, pkt_data);

        if (t_MsgCon.Length > 0)
        {
            if (t_MsgCon.Length == 1 && t_MsgCon.Data.at(0) == 0x00)	//过滤长度=1并且数据为0的数据包（可能是握手成功的数据包）
                break;

            //时差
            t_MsgCon.TimeDifference = getTimeDifference(header->ts.tv_sec, header->ts.tv_usec);

            QMutexLocker locker(&G_QueneMutex);
            G_RecvQueue.enqueue(t_MsgCon);
            G_RecvCondition.wakeOne();
        }
        break;
    case IPPROTO_UDP:
        UDP(t_MsgCon, t_IPLength, pkt_data);
        if (t_MsgCon.Length > 0)
        {
            //时差
            t_MsgCon.TimeDifference = getTimeDifference(header->ts.tv_sec, header->ts.tv_usec);
        }
		return;
    case IPPROTO_ICMP:
        //qDebug() << QString("   Protocol: ICMP");
		return;
	case IPPROTO_IP:
		//qDebug() << QString("   Protocol: IP");
		return;
	default:
		//qDebug() << QString("   Protocol: unknown");
		return;
    }

    //计算时间 TODO: WW 待添加的时间戳信息，用于描述每一条独立的记录信息
    //struct tm *ltime;
    //char timestr[16];
    //time_t local_tv_sec;
    //// 将时间戳转换成可识别的格式
    //local_tv_sec = header->ts.tv_sec;
    //ltime = localtime(&local_tv_sec);
    //strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    //// 打印数据包的时间戳和数据包长度
    //qDebug() << QString("时间戳 秒：[%1] // [%2]  /n微秒 [%3]").arg(timestr).arg(header->ts.tv_sec)
    //	.arg(header->ts.tv_usec);
}


/**
 * @brief PcapThread::TCP					TCP报文解析
 * @param[out] MsgCon						解析后信息
 * @param[in] int iPLength					IP头长度
 * @param[in] uint len						报文总长度
 * @param[in] const unsigned char *pkt_data	报文包数据
 */
void PcapThread::TCP(MessageContent &MsgCon, int iPLength, unsigned int len, const unsigned char *pkt_data)
{
    const struct sniff_tcp *tcp;		// TCP头
    int size_tcp;

    // 定义/计算tcp头偏移量
    tcp = (struct sniff_tcp*)(pkt_data + SIZE_ETHERNET + iPLength);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        //qDebug() << QString("     Invalid TCP header length: %1 bytes").arg(size_tcp);
        return;
    }

    MsgCon.Type = ProtocolType::TCP;
    MsgCon.SrcPoet = ntohs(tcp->th_sport);
    MsgCon.DstPoet = ntohs(tcp->th_dport);

    // 计算有效载荷大小
    int size_payload = len - (SIZE_ETHERNET + iPLength + size_tcp);
    MsgCon.Length = size_payload;
    // 计算有效载荷
    if (size_payload > 0) {
        //获取除去网络头+IP协议头+TCP协议头长度之后数据长度为size_payload的数据信息
        QByteArray tByte((char *)(pkt_data + SIZE_ETHERNET + iPLength + size_tcp), size_payload);
        MsgCon.Data = tByte;

        // 打印有效载荷信息它可能是二进制的，所以不要只是将其视为一个字符串。
        //print_payload(payload, size_payload);
    }
}


/**
 * @brief PcapThread::UDP   UDP报文解析
 * @param MsgCon            解析后信息
 * @param iPLength          IP头长度
 * @param pkt_data          报文包数据
 */
void PcapThread::UDP(MessageContent &MsgCon, int iPLength, const unsigned char *pkt_data)
{
    udp_header *udp_h;		//UDP头

    // 定义/计算tcp头偏移量
    udp_h = (udp_header*)(pkt_data + SIZE_ETHERNET + iPLength);

    MsgCon.Type = ProtocolType::UDP;
    MsgCon.SrcPoet = ntohs(udp_h->sport);
    MsgCon.DstPoet = ntohs(udp_h->dport);

    // 计算有效载荷大小
    int size_payload = ntohs(udp_h->len) - 8;
    MsgCon.Length = size_payload;
    // 计算有效载荷
    if (size_payload > 0) {
        //获取除去网络头+IP协议头+TCP协议头长度之后数据长度为size_payload的数据信息
        QByteArray tByte((char *)(pkt_data + SIZE_ETHERNET + iPLength + SIZE_UDPHEADER_LEN), size_payload);
        MsgCon.Data = tByte;
    }
}


/**
 * @brief PcapThread::print_payload  打印包有效载荷数据（避免打印二进制数据）
 * @param payload
 * @param len
 */
void PcapThread::print_payload(const unsigned char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;			// 每行的字节数
    int line_len;
    int offset = 0;					// 从零开始的偏移计数器
    const unsigned char *ch = payload;

    if (len <= 0)
        return;

    // data fits on one line
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    // data spans multiple lines
    for (;; ) {
        // 计算当前行长度
        line_len = line_width % len_rem;
        // 打印线
        print_hex_ascii_line(ch, line_len, offset);
        // 计算剩余总数
        len_rem = len_rem - line_len;
        // 将指针移动到要打印的剩余字节
        ch = ch + line_len;
        // 添加偏移量
        offset = offset + line_width;
        // 检查我们是否有线宽字符或更少
        if (len_rem <= line_width) {
            // 打印最后一行然后离开
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}


/**
 * @brief PcapThread::print_hex_ascii_line  以16字节为单位打印数据：偏移十六进制ascii
 * @param payload   数据包数据
 * @param len       数据包长度
 * @param offset    数据包
 */
void PcapThread::print_hex_ascii_line(const unsigned char *payload, int len, int offset)
{
    int i;
    int gap;
    const unsigned char *ch;

    // offset
    qDebug() << QString("%1   ").arg(offset);

    // hex
    ch = payload;
    for (i = 0; i < len; i++) {
        qDebug() << QString("%1 ").arg(*ch);
        ch++;
        // print extra space after 8th byte for visual aid
        if (i == 7)
            qDebug() << QString(" ");
    }
    // print space to handle line less than 8 bytes
    if (len < 8)
        qDebug() << QString(" ");

    // fill hex gap with spaces if not full line
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            qDebug() << QString("   ");
        }
    }
    qDebug() << QString("   ");

    // ascii (if printable)
    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            qDebug() << QString("%1").arg(*ch);
        else
            qDebug() << QString(".");
        ch++;
    }

    qDebug() << QString("");

    return;
}


/**
 * @brief PcapThread::getTimeDifference 计算时间差
 * @param timesec   秒数
 * @param timeusec  微秒(* 0.000001)转换为秒
 * @return 与上个数据包相隔时间
 */
double PcapThread::getTimeDifference(long timesec ,long timeusec)
{
    static double time1 = 0;
    static double time2 = 0;
    double TimeDifference = 0.0;	//时间

    if (time1 == 0)
    {
        time2 = time1 = timesec + (timeusec*0.000001);	//记录第一次
        return 0.0;
    }
    else
    {
        time1 = timesec + (timeusec*0.000001);
        TimeDifference = time1 - time2;		//计算时间差
        time2 = time1;		//将本次时间更新，方便下次计算
    }
    return TimeDifference;
}
