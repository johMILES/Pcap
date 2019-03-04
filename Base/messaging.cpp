#include "messaging.h"


static Messaging *g_pMessaging = NULL;
Messaging::Messaging()
{
    g_pMessaging = this;
}


Messaging::~Messaging()
{
}


Messaging* Messaging::getInstance()
{
    if (!g_pMessaging)
        new Messaging();

    return g_pMessaging;
}


/**
 * @brief Messaging::messageMenubar 状态栏信息提示
 * @param str   状态栏显示信息
 */
void Messaging::messageMenubar(QString str)
{
    emit messageMenubar_signal(str);
}


/**
 * @brief Messaging::messageDefaultPath
 * @param path
 */
void Messaging::messageDefaultPath(QString path)
{
    emit messageDefPath_signal(path);
}
