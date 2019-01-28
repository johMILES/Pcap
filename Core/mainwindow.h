#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMap>

#include "Public.h"

class QCloseEvent;
class QLabel;
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
    void slot_actionOpen_triggered();
    void slot_actionExit_triggered();
    void slot_actionSeting_triggered();

protected:
    void closeEvent(QCloseEvent *event);

private:
    void initWidget();
    void initPcap();
    void initDefaultSavePath();
    bool getPort();
    void showStatusBar(QString);

private:
    Ui::MainWindow *ui;
    PcapCommon *m_pPcap;
    QMap<int, _DEVInfo> m_DeviceList;

private:
    QString m_FilePath;
    bool m_bFlag;	//是否正在抓包标志

    QLabel *m_pPermanentStatusbar;
};

#endif // MAINWINDOW_H
