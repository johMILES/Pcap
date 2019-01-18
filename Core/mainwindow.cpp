#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "PcapCommon.h"

#include <QCloseEvent>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_Port = 0;
    m_pPcap = NULL;

    initWidget();
}

MainWindow::~MainWindow()
{
    delete ui;
}

/*!
 * 初始化界面信息
 */
void MainWindow::initWidget()
{
    m_bFlag = false;

    if(m_pPcap == NULL)
    {
        initPcap();
    }

    //按钮
    connect(ui->Start_Btn, SIGNAL(clicked(bool)), this, SLOT(slot_Airodump_ng_Button()));
}

/*!
 * @brief 初始化Pcap组件
 */
void MainWindow::initPcap()
{
    if(m_pPcap == NULL)
    {
        m_pPcap = new PcapCommon();
        m_pPcap->winSocketInit();

        //获取本机适配器列表，将列表填充在下拉框中
        QVector<_DEVInfo> devInfo(m_pPcap->findAllDev());
        if (devInfo.isEmpty())
        {
            ui->Prompt_TextEdit->setPlainText(tr("The device's adapter is empty!"));
            return;
        }

        m_DeviceList.clear();
        ui->Card_ComboBox->clear();
        for (int i = 0; i < devInfo.count(); i++)
        {
            ui->Card_ComboBox->addItem(devInfo.at(i).description);
            m_DeviceList.insert(i, devInfo.at(i));
        }
    }
}

/*!
 * @brief 窗口退出事件
 * @param event 退出事件对象
 */
void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_bFlag)
    {
        QMessageBox::StandardButton res = QMessageBox::warning(this, tr("warning"), tr("in working ,exit?"),
                                                               QMessageBox::Yes | QMessageBox::No);//正在抓包中，是否退出？
        if (res == QMessageBox::StandardButton::Yes)
        {
            if(m_pPcap)
            {
                m_pPcap->closeCard();
            }
            event->accept();		//接受信息 程序退出
            return;
        }
        event->ignore();		//忽略信号，程序继续运行
    }
}

/*!
 * @brief 开始抓包
 */
void MainWindow::slot_Airodump_ng_Button()
{
    if(m_pPcap == NULL)
    {
        initPcap();
    }
    if (!m_bFlag)
    {
        // 1打开适配器
        if (!getPort())
        {
            QMessageBox::warning(this, tr("Warning"), tr("Port number error"));
            return;
        }
        m_pPcap->SetPort(m_Port);
        const _DEVInfo devinfo = m_DeviceList.find(ui->Card_ComboBox->currentIndex()).value();
        if (!m_pPcap->openCard(devinfo))
        {
            ui->Prompt_TextEdit->setPlainText(tr("Connection Failed!"));
            return;
        }

        ui->Prompt_TextEdit->setPlainText(tr("Connection Succeeded..."));

        ui->Prompt_TextEdit->append(tr("SavePath:")+m_pPcap->m_SelectPath);

        ui->Start_Btn->setText(tr("End"));
        m_bFlag = true;
    }
    else
    {
        //关闭并停止线程
        m_pPcap->closeCard();
        ui->Prompt_TextEdit->append(tr("Disconnected"));
        ui->Start_Btn->setText(tr("Start"));
        m_bFlag = false;
    }
}

/*!
 * @brief 读取备份数据文件
 */
void MainWindow::on_actionOpen_triggered()
{
    if(m_pPcap == NULL)
    {
        initPcap();
    }
    if(m_pPcap)
    {
        m_pPcap->readDatFile();
    }
}


/*!
 * @brief 获取端口号
 */
bool MainWindow::getPort()
{
    int port = ui->Port_LineEdit->text().toInt();
    if (port<1 || port>0xFFFF)
    {
        return false;
    }
    else
    {
        m_Port = port;
        return true;
    }
}
