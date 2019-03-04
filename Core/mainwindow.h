#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QMap>

#include "Public.h"
#include "playback.h"

class QCloseEvent;
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
    void slot_actionOpen_triggered();
    void slot_actionSeting_triggered();

    void slot_actionOption_triggered();
    void slot_actionStart_triggered();
    void slot_actionStop_triggered();

    void slot_showStatusBar(QString msg);
    void slot_UpdateDefPathLabel(QString path);
    void slot_OpenDefaultPath(QString path);

protected:
    void closeEvent(QCloseEvent *event);

private:
    void selectAdapter();
    void initMenu();
    void initPcap();
    void initWidget();
    void initDefaultSavePath();
    bool setCaptureInfo();

private:
    Ui::MainWindow *ui;
    Playback *m_pPlayback;
    QVector<_DEVInfo> m_DevInfo;
    QMap<int, _DEVInfo> m_DeviceList;

    QLabel *m_pDefaultPath;
    int m_iAterlIndex;
    QString m_szFilePath;
    bool m_bIsSetCaptureInfoFlag;   //是否设置了捕获信息
	bool m_bFlag;	//是否正在抓包标志

};

#endif // MAINWINDOW_H
