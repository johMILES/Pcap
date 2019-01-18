#include "TransferSignas.h"


TransferSignas::TransferSignas()
{
	//thread = new PcapThread;
	//connect(thread, SIGNAL(signal_Data(QString)), this, SLOT(slot_test(QString)), Qt::QueuedConnection);
}


TransferSignas::~TransferSignas()
{
}

void TransferSignas::slot_test(QString str)
{
	emit signals_test(str);
}