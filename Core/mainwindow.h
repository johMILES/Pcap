#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMap>

#include "Public.h"

class QCloseEvent;
class PcapCommon;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void slot_Airodump_ng_Button();
    void on_actionOpen_triggered();

protected:
    void closeEvent(QCloseEvent *event);

private:
    void initWidget();
    void initPcap();

private:
    Ui::MainWindow *ui;
    PcapCommon *m_pPcap;
    QMap<int, _DEVInfo> m_DeviceList;

private:
    unsigned short m_Port;
    bool m_bFlag;	//是否正在抓包标志
};

#endif // MAINWINDOW_H
