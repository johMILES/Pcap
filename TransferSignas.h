#pragma once

#include <qobject.h>

#include "PcapThread.h"

class TransferSignas : public QObject
{
	Q_OBJECT
public:
	TransferSignas();
	~TransferSignas();

Q_SIGNALS:
	void signals_test(QString);


private slots:
	void slot_test(QString);
		//
private:
	PcapThread *thread;

};

