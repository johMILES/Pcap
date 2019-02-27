
#include <QIcon>
#include <QDebug>
#include <QCloseEvent>
#include <QMessageBox>
#include <QFileDialog>
#include <QApplication>
#include <QDesktopServices>

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Base/messaging.h"
#include "PcapCommon.h"
#include "optionwidget.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //��ʼ��Pcap
    initPcap();
    //���ұ���������
    selectAdapter();
    //��ʼ���˵�
    initMenu();

    //
    initWidget();

    //��ʼ��Ĭ�ϱ���·��
    initDefaultSavePath();
}


MainWindow::~MainWindow()
{
    delete ui;


    if (!m_pPlayback)
    {
        delete m_pPlayback;
        m_pPlayback = NULL;
    }

//    if (m_pPcap != NULL)
//    {
//        delete m_pPcap;
//        m_pPcap = NULL;
//    }
}


/**
 * @brief MainWindow::initPcap  ��ʼ��������Ϣ
 */
void MainWindow::initPcap()
{
    m_bIsSetCaptureInfoFlag = false;
	m_bFlag = false;
    m_iAterlIndex = 0;
//    m_pPcap = NULL;

//    if(m_pPcap == NULL)
//    {
//        m_pPcap = new PcapCommon();
//        m_pPcap->winSocketInit();
//    }
}


/**
 * @brief MainWindow::selectAdapter  ��ȡ�������б�
 */
void MainWindow::selectAdapter()
{
    //��ȡ�����������б����б��������������
    m_DevInfo = PcapCommon::getInstance()->getAllDev();
    if (m_DevInfo.isEmpty())
    {
        return;
    }
    m_DeviceList.clear();
    for (int i = 0; i < m_DevInfo.count(); i++)
    {
        m_DeviceList.insert(i, m_DevInfo.at(i));
    }
}


/**
 * @brief MainWindow::initMenu  ��ʼ���˵���
 */
void MainWindow::initMenu()
{
    ui->actionOpen->setIcon(QIcon(":/Menu/folder.png"));
    ui->actionExit->setIcon(QIcon(":/Menu/exit.png"));
    ui->actionDefaultPath->setIcon(QIcon(":/Menu/settings.png"));
    ui->actionStart->setIcon(QIcon(":/Menu/start.png"));
    ui->actionStop->setIcon(QIcon(":/Menu/stop.png"));

    ui->actionStop->setEnabled(false);

    if (m_DevInfo.count()<=0)
    {
        ui->menu_2->setEnabled(false);
        ui->actionDefaultPath->setEnabled(false);
    }

    //�ļ�:
    //���ļ�
    QObject::connect(ui->actionOpen, SIGNAL(triggered(bool))
                     , this, SLOT(slot_actionOpen_triggered()));
    //�˳�
    QObject::connect(ui->actionExit, SIGNAL(triggered(bool))
                     , this, SLOT(close()));
    //���ߣ�
    //����Ĭ��·��
    QObject::connect(ui->actionDefaultPath, SIGNAL(triggered(bool))
                     , this, SLOT(slot_actionSeting_triggered()));

    //����:
    //ѡ��
    QObject::connect(ui->actionOption, SIGNAL(triggered(bool))
                     , this, SLOT(slot_actionOption_triggered()));
    //��ʼ
    QObject::connect(ui->actionStart, SIGNAL(triggered(bool))
                     , this, SLOT(slot_actionStart_triggered()));
    //ֹͣ
    QObject::connect(ui->actionStop, SIGNAL(triggered(bool))
                     , this, SLOT(slot_actionStop_triggered()));

    //StatusBar:
    QObject::connect(Messaging::getInstance(), SIGNAL(messageMenubar_signal(QString))
                     , this, SLOT(slot_showStatusBar(QString)));

    QObject::connect(Messaging::getInstance(), SIGNAL(messageDefPath_signal(QString))
                     , this, SLOT(slot_UpdateDefPathLabel(QString)));
}


/**
 * @brief MainWindow::initWidget   ��ʼ��Widget
 */
void MainWindow::initWidget()
{
    m_pDefaultPath = new QLabel(m_szFilePath);
    connect(m_pDefaultPath, SIGNAL(linkActivated(QString))
            , this, SLOT(slot_OpenDefaultPath(QString)));

    statusBar()->addPermanentWidget(m_pDefaultPath);


    m_pPlayback = NULL;

    if (!m_pPlayback)
    {
        m_pPlayback = new Playback(this);
        m_pPlayback->setWindowTitle("Playback");
        m_pPlayback->move(0,30);
        m_pPlayback->hide();
    }
}


/**
 * @brief MainWindow::initDefaultSavePath   ����Ĭ�ϱ����ļ�·��
 */
void MainWindow::initDefaultSavePath()
{
    QString t_DefaultPath = QApplication::applicationDirPath()+ "/" + tr("CaptureFile");

    QDir dir(t_DefaultPath);
    if (!dir.exists())
    {
		if (!dir.mkpath(t_DefaultPath))
		{
            t_DefaultPath = QApplication::applicationDirPath();
        }
    }
    Messaging::getInstance()->messageDefaultPath(t_DefaultPath);
}


/**
 * @brief MainWindow::setCaptureInfo    ��ʾ������ץ����Ϣ
 * @return  �Ƿ����óɹ�
 */
bool MainWindow::setCaptureInfo()
{
    OptionWidget tOptionWidget;
    tOptionWidget.setCheckBox(m_DevInfo);
    int r = tOptionWidget.exec();

    if (r == QDialog::Accepted)
    {
        PcapCommon::getInstance()->setPort(tOptionWidget.getPort());
        m_iAterlIndex = tOptionWidget.getAdapterIndex();
        m_bIsSetCaptureInfoFlag = true;

        return true;
    }
    else
    {
        return false;
    }
}


/**
 * @brief MainWindow::closeEvent  �����˳��¼�
 * @param event  �˳��¼�����
 */
void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_bFlag)
    {
        QMessageBox::StandardButton res = QMessageBox::warning(this, tr("warning"), tr("in working ,exit?"),
                                                               QMessageBox::Yes | QMessageBox::No);//����ץ���У��Ƿ��˳���
        if (res == QMessageBox::StandardButton::Yes)
        {
            event->accept();		//�����ź� �����˳�
            return;
        }
        event->ignore();		//�����źţ������������
    }
}


/**
 * @brief MainWindow::slot_actionStart_triggered  ��ʼץ����ť�¼�
 */
void MainWindow::slot_actionStart_triggered()
{
    if (!m_bIsSetCaptureInfoFlag)
    {
        if (!setCaptureInfo())
        {
            Messaging::getInstance()->messageMenubar(tr("Configuration settings failed"));
            return;
        }
    }
    if (!m_bFlag)
    {
        PcapCommon::getInstance()->setFilePath(m_szFilePath);
        const _DEVInfo devinfo = m_DeviceList.find(m_iAterlIndex).value();
        //��������
        if (!PcapCommon::getInstance()->openCard(devinfo))
        {
            Messaging::getInstance()->messageMenubar(tr("Turn on capture failure"));
            return;
        }
        //��ʼץ��
        PcapCommon::getInstance()->startCapturing(devinfo);

        ui->actionOpen->setEnabled(m_bFlag);
        ui->actionDefaultPath->setEnabled(m_bFlag);
        ui->actionOption->setEnabled(m_bFlag);
        ui->actionStart->setEnabled(m_bFlag);

        m_bFlag = !m_bFlag;
        ui->actionStop->setEnabled(m_bFlag);
    }
}


/**
 * @brief MainWindow::slot_actionStop_triggered  ֹͣץ��
 */
void MainWindow::slot_actionStop_triggered()
{
    if (m_bFlag)
    {
        //�رղ�ֹͣ�߳�
        PcapCommon::getInstance()->closeCard();

        ui->actionOpen->setEnabled(m_bFlag);
        ui->actionDefaultPath->setEnabled(m_bFlag);
        ui->actionOption->setEnabled(m_bFlag);
        ui->actionStart->setEnabled(m_bFlag);

        m_bFlag = !m_bFlag;
        ui->actionStop->setEnabled(m_bFlag);
    }
}

/**
 * @brief MainWindow::on_actionOpen_triggered  �˵�����ȡ���������ļ�
 */
void MainWindow::slot_actionOpen_triggered()
{
    //ѡ����ץ���ļ�·��
    QString file_path = QFileDialog::getOpenFileName(this, tr("select file"), QApplication::applicationDirPath()+tr("/CaptureFile"), "*.dat");
    if (file_path.isEmpty())
    {
        return;
    }
    m_pPlayback->show();
    m_pPlayback->setCheckBox(PcapCommon::getInstance()->getAllDev());
    m_pPlayback->setFilePath(file_path);
}


/**
 * @brief MainWindow::slot_actionSeting_triggered  ���ñ��沶�񵽱���·��
 */
void MainWindow::slot_actionSeting_triggered()
{
    //ѡ����ץ���ļ�·��
    QString file_path = QFileDialog::getExistingDirectory(this, tr("Save File Path..."), m_szFilePath);
    if (file_path.isEmpty())
    {
        return;
    }
    Messaging::getInstance()->messageDefaultPath(file_path);
}


/**
 * @brief MainWindow::slot_actionOption_triggered  ����Ĭ��ץ������
 */
void MainWindow::slot_actionOption_triggered()
{
    setCaptureInfo();
}


/**
 * @brief MainWindow::slot_showStatusBar  ��ʾ״̬
 * @param str  ״̬����
 */
void MainWindow::slot_showStatusBar(QString msg)
{
    statusBar()->showMessage(msg);
    //ui->statusbar->showMessage(msg);
}


/**
 * @brief MainWindow::slot_UpdateDefPathLabel
 * @param path
 */
void MainWindow::slot_UpdateDefPathLabel(QString path)
{
    m_szFilePath = path;

    QString Hypertext = QString("<a href = \"%1\">%2</a>").arg(path).arg(path);
    m_pDefaultPath->setText(Hypertext);
}


/**
 * @brief MainWindow::slot_OpenDefaultPath   ����Դ��ͼ�д�
 * @param path  ·��
 */
void MainWindow::slot_OpenDefaultPath(QString path)
{
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}
