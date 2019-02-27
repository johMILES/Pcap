#include "mydealthread.h"
#include "gloab.h"

#include <QDataStream>
#include <QDebug>

MyDealThread::MyDealThread(QString path, QObject *parent)
    : QThread(parent)
{
    m_pPath = path;
	m_pWriteFile = new QFile(m_pPath);
}


MyDealThread::~MyDealThread()
{
    qDebug()<<"MyDealThread::~MyDealThread()";
    if (m_pWriteFile)
    {
        if (m_pWriteFile->isOpen())
            m_pWriteFile->close();

		delete m_pWriteFile;
		m_pWriteFile = NULL;
	}
}


/**
 * @brief MyDealThread::setFilePath  设置写入文件全路径
 * @param path  文件路径
 */
void MyDealThread::setFilePath(QString path)
{
    if (m_pWriteFile)
    {
        if (m_pWriteFile->isOpen())
            m_pWriteFile->close();

        delete m_pWriteFile;
        m_pWriteFile = NULL;
    }
	m_pWriteFile = new QFile(path);
}


/**
 * @brief MyDealThread::stopCapturing  停止捕获
 */
void MyDealThread::stopCapturing()
{
    if (m_pWriteFile)
    {
        if (m_pWriteFile->isOpen())
            m_pWriteFile->close();
    }
}

void MyDealThread::run()
{
	if (!m_pWriteFile->isOpen())
	{
		if (!m_pWriteFile->open(QIODevice::WriteOnly | QIODevice::Append/* | QIODevice::Truncate | QIODevice::Text*/))
			return;
	}

    while(b_isWork)
    {
        while(G_RecvQueue.size() == 0)
        {
            G_WaitMutex.lock();
            G_RecvCondition.wait(&G_WaitMutex);
            G_WaitMutex.unlock();
        }

        QMutexLocker locker(&G_QueneMutex);
        MessageContent t_get_array =  G_RecvQueue.dequeue();
        outFile(t_get_array);
    }
}

/**
 * @brief MyDealThread::outFile  将要输出数据保存在文件中（若单次或累计写入文件间隔时间大于1秒则关闭重新打开文件一次
 * 确保抓包写入文件内容时在软件发生异常数据不丢失）
 * @param in_data   将要写入文件数据信息
 */
void MyDealThread::outFile(MessageContent in_data)
{
    static double time = 0;
    static bool flag = false;
    if (flag)
    {
        if (!m_pWriteFile->isOpen())
        {
            if (!m_pWriteFile->open(QIODevice::Append))
                return;
        }
        flag = false;
    }

    //写入文件
    QDataStream out(m_pWriteFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_ip = inet_ntoa(in_data.SrcAddress);
    QByteArray dst_ip = inet_ntoa(in_data.DstAddress);	//收发IP转换

    out << src_ip.data() << dst_ip.data()
        << in_data.SrcPoet << in_data.DstPoet
        << QByteArray::number(in_data.TimeDifference, 'E') << in_data.Data.toHex().data();

    time += in_data.TimeDifference;
    if (time > 1)
    {
        time = 0;
        flag = true;
        m_pWriteFile->close();
    }
}


