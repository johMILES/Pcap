#include "gloab.h"

QQueue<QByteArray> G_RecvQueue;
QMutex G_QueneMutex;
QWaitCondition G_WaitCondition;

