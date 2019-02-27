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
 * @brief MyDealThread::setFilePath  ����д���ļ�ȫ·��
 * @param path  �ļ�·��
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
 * @brief MyDealThread::stopCapturing  ֹͣ����
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
 * @brief MyDealThread::outFile  ��Ҫ������ݱ������ļ��У������λ��ۼ�д���ļ����ʱ�����1����ر����´��ļ�һ��
 * ȷ��ץ��д���ļ�����ʱ�����������쳣���ݲ���ʧ��
 * @param in_data   ��Ҫд���ļ�������Ϣ
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

    //д���ļ�
    QDataStream out(m_pWriteFile);
    out.setVersion(QDataStream::Qt_5_7);

    QByteArray src_ip = inet_ntoa(in_data.SrcAddress);
    QByteArray dst_ip = inet_ntoa(in_data.DstAddress);	//�շ�IPת��

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

