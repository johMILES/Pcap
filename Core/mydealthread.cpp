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
	if (m_pWriteFile->isOpen())
	{
		m_pWriteFile->close();
		delete m_pWriteFile;
		m_pWriteFile = NULL;
	}
}


void MyDealThread::setFilePath(QString path)
{
	m_pWriteFile = new QFile(path);
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

    QDataStream out(m_pWriteFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_ip = inet_ntoa(in_data.SrcAddress);
    QByteArray dst_ip = inet_ntoa(in_data.DstAddress);	//ÊÕ·¢IP×ª»»

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


