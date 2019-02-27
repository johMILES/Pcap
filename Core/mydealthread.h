#ifndef MYDEALTHREAD_H
#define MYDEALTHREAD_H

#include <QThread>
#include <QFile>

#include "Public.h"

class MyDealThread : public QThread
{
	Q_OBJECT
public:
    explicit MyDealThread(QString path, QObject *parent = 0);
	~MyDealThread();

	void setFilePath(QString path);
    void stopCapturing();

public:
	void run();

private:
    void outFile(MessageContent in_data);

private:
	QString m_pPath;
	QFile *m_pWriteFile;
	bool b_isWork;

};

#endif // MYDEALTHREAD_H
