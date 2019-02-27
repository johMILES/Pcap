#ifndef GLOAB_H
#define GLOAB_H

#include <QMutex>
#include <QQueue>
#include <QWaitCondition>

#include "Public.h"

extern QQueue<MessageContent> G_RecvQueue;
extern QMutex G_QueneMutex;
extern QMutex G_WaitMutex;
extern QWaitCondition G_RecvCondition;


#endif // GLOAB_H
