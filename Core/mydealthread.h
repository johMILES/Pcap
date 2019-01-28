#ifndef MYDEALTHREAD_H
#define MYDEALTHREAD_H

#include <QThread>

class MyDealThread : public QThread
{
    Q_OBJECT
public:
    explicit MyDealThread(QObject *parent = 0);

protected:
    void run();

signals:

public slots:

private:
    void dealRecvArray(QByteArray in_data);

private:
    bool b_isWork;

};

#endif // MYDEALTHREAD_H
