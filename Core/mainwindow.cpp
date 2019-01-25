#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "PcapCommon.h"

#include <QDebug>
#include <QCloseEvent>
#include <QMessageBox>
#include <QFileDialog>
#include <QApplication>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_pPcap = NULL;

    initWidget();
    initDefaultSavePath();

}

MainWindow::~MainWindow()
{
    delete ui;
}

/**
 * @brief MainWindow::initWidget  初始化界面信息
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
    ////Menu事件
    //文件：   打开文件
    connect(ui->actionOpen, SIGNAL(triggered(bool)), this, SLOT(slot_actionOpen_triggered()));
    connect(ui->actionExit, SIGNAL(triggered(bool)), this, SLOT(slot_actionExit_triggered()));
    //工具：   设置
    connect(ui->actionSetting, SIGNAL(triggered(bool)), this, SLOT(slot_actionSeting_triggered()));
}

/**
 * @brief MainWindow::initPcap  初始化Pcap组件
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

/**
 * @brief MainWindow::initDefaultSavePath   设置默认保存文件路径
 */
void MainWindow::initDefaultSavePath()
{
    m_FilePath = QApplication::applicationDirPath()+ "/" + tr("CaptureFile");
    QDir dir(m_FilePath);
    if (!dir.exists())
    {
        dir.mkpath(m_FilePath);
    }

    m_pPermanentStatusbar = new QLabel(tr("Current save file path: ")+m_FilePath, this);
    ui->statusbar->addPermanentWidget(m_pPermanentStatusbar);
}

/**
 * @brief MainWindow::closeEvent  窗口退出事件
 * @param event  退出事件对象
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
            event->accept();		//接受信号 程序退出
            return;
        }
        event->ignore();		//忽略信号，程序继续运行
    }
}


/*!
 * \brief MainWindow::slot_Airodump_ng_Button  开始抓包按钮事件
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

        m_pPcap->setFilePath(m_FilePath);
        const _DEVInfo devinfo = m_DeviceList.find(ui->Card_ComboBox->currentIndex()).value();
        if (!m_pPcap->openCard(devinfo))
        {
            ui->Prompt_TextEdit->setPlainText(tr("Connection Failed!"));
            return;
        }

        ui->Prompt_TextEdit->setPlainText(tr("Connection Succeeded..."));
        ui->Start_Btn->setText(tr("End"));
    }
    else
    {
        //关闭并停止线程
        m_pPcap->closeCard();
        ui->Prompt_TextEdit->append(tr("Disconnected"));
        ui->Start_Btn->setText(tr("Start"));
    }

    ui->Card_ComboBox->setEnabled(m_bFlag);
    ui->Port_LineEdit->setEnabled(m_bFlag);

    m_bFlag = !m_bFlag;
}

/*!
 * \brief MainWindow::on_actionOpen_triggered  菜单：读取备份数据文件
 */
void MainWindow::slot_actionOpen_triggered()
{
    if(m_pPcap == NULL)
    {
        initPcap();
    }
    if(m_pPcap)
    {
        //选择存放抓包文件路径
        QString file_path = QFileDialog::getOpenFileName(this, tr("select file"), QApplication::applicationDirPath()+tr("/CaptureFile"), "*.dat");
        if (file_path.isEmpty())
        {
            return;
        }
        m_pPcap->readDatFile(file_path);
    }
}

/**
 * @brief MainWindow::slot_actionExit_triggered  菜单：退出软件
 */
void MainWindow::slot_actionExit_triggered()
{
    this->close();
}
/**
 * @brief MainWindow::slot_actionSeting_triggered  设置保存捕获到报文路径
 */
void MainWindow::slot_actionSeting_triggered()
{
    //选择存放抓包文件路径
    QString file_path = QFileDialog::getExistingDirectory(this, tr("Save File Path..."), m_FilePath);
    if (file_path.isEmpty())
    {
        return;
    }
    m_FilePath = tr("Current save file path: ")+file_path;
    m_pPermanentStatusbar->setText(m_FilePath);
    ui->statusbar->addPermanentWidget(m_pPermanentStatusbar);
}


/*!
 * \brief MainWindow::getPort  获取端口号
 * \return  true端口号符合条件
 */
bool MainWindow::getPort()
{
    unsigned short port = ui->Port_LineEdit->text().toInt();
    if (port<1 || port>0xFFFF)
    {
        return false;
    }
    else
    {
        m_pPcap->setPort(port);
        return true;
    }
}
