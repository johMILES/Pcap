#include "gloab.h"

QQueue<MessageContent> G_RecvQueue;
QMutex G_QueneMutex;
QMutex G_WaitMutex;
QWaitCondition G_RecvCondition;

