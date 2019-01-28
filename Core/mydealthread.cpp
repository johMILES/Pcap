#include "mydealthread.h"
#include "gloab.h"
#include <QMutexLocker>
#include <QDebug>

MyDealThread::MyDealThread(QObject *parent) : QThread(parent)
{

}

void MyDealThread::run()
{
    while(b_isWork)
    {
        while(G_RecvQueue.size() == 0)
        {
            G_RecvCondition.wait(&G_QueneMutex);
        }

        QMutexLocker locker(&G_QueneMutex);
        QByteArray t_get_array =  G_RecvQueue.dequeue ();
        dealRecvArray(t_get_array);
    }
}

void MyDealThread::dealRecvArray(QByteArray in_data)
{
    qDebug()<<__FILE__<<__FUNCTION__<<__LINE__<<__DATE__<<__TIME__<<"\n"
           <<in_data
           <<"\n";
}


