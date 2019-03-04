#ifndef MESSAGING_H
#define MESSAGING_H

#include <QObject>
#include <QString>

class Messaging : public QObject
{
    Q_OBJECT
signals:
    void messageMenubar_signal(QString str);
    void messageDefPath_signal(QString str);

public:
    static Messaging* getInstance();

    void messageMenubar(QString str);
    void messageDefaultPath(QString path);

private:
    Messaging();
    ~Messaging();

};

#endif // MESSAGING_H
