#ifndef PLAYBACK_H
#define PLAYBACK_H

#include <QObject>
#include <QDialog>
#include <QPushButton>
#include <QComboBox>
#include <QString>

#include "Public.h"

class Playback : public QWidget
{
    Q_OBJECT
public:
    explicit Playback(QWidget *parent = 0);
    ~Playback();

    void setFilePath(QString path);
    void setCheckBox(QVector<_DEVInfo> devs);

private slots:
    void fileBtn_slot();
    void cancelPlayback_slot();

private:
    QPushButton *m_pFileBtn;
    QPushButton *m_pCancelPlayback;
    QComboBox *m_pAdapterComboBox;

    QVector<_DEVInfo> m_DevInfo;
    QString m_csFilePath;

    void initWidget();

    //读取抓包文件
    void StartPlayback(QString path);

};

#endif // PLAYBACK_H
