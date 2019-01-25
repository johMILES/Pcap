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
 * @brief MainWindow::initWidget  ��ʼ��������Ϣ
 */
void MainWindow::initWidget()
{
    m_bFlag = false;

    if(m_pPcap == NULL)
    {
        initPcap();
    }

    //��ť
    connect(ui->Start_Btn, SIGNAL(clicked(bool)), this, SLOT(slot_Airodump_ng_Button()));
    ////Menu�¼�
    //�ļ���   ���ļ�
    connect(ui->actionOpen, SIGNAL(triggered(bool)), this, SLOT(slot_actionOpen_triggered()));
    connect(ui->actionExit, SIGNAL(triggered(bool)), this, SLOT(slot_actionExit_triggered()));
    //���ߣ�   ����
    connect(ui->actionSetting, SIGNAL(triggered(bool)), this, SLOT(slot_actionSeting_triggered()));
}

/**
 * @brief MainWindow::initPcap  ��ʼ��Pcap���
 */
void MainWindow::initPcap()
{
    if(m_pPcap == NULL)
    {
        m_pPcap = new PcapCommon();
        m_pPcap->winSocketInit();

        //��ȡ�����������б����б��������������
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
 * @brief MainWindow::initDefaultSavePath   ����Ĭ�ϱ����ļ�·��
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
            if(m_pPcap)
            {
                m_pPcap->closeCard();
            }
            event->accept();		//�����ź� �����˳�
            return;
        }
        event->ignore();		//�����źţ������������
    }
}


/*!
 * \brief MainWindow::slot_Airodump_ng_Button  ��ʼץ����ť�¼�
 */
void MainWindow::slot_Airodump_ng_Button()
{
    if(m_pPcap == NULL)
    {
        initPcap();
    }
    if (!m_bFlag)
    {
        // 1��������
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
        //�رղ�ֹͣ�߳�
        m_pPcap->closeCard();
        ui->Prompt_TextEdit->append(tr("Disconnected"));
        ui->Start_Btn->setText(tr("Start"));
    }

    ui->Card_ComboBox->setEnabled(m_bFlag);
    ui->Port_LineEdit->setEnabled(m_bFlag);

    m_bFlag = !m_bFlag;
}

/*!
 * \brief MainWindow::on_actionOpen_triggered  �˵�����ȡ���������ļ�
 */
void MainWindow::slot_actionOpen_triggered()
{
    if(m_pPcap == NULL)
    {
        initPcap();
    }
    if(m_pPcap)
    {
        //ѡ����ץ���ļ�·��
        QString file_path = QFileDialog::getOpenFileName(this, tr("select file"), QApplication::applicationDirPath()+tr("/CaptureFile"), "*.dat");
        if (file_path.isEmpty())
        {
            return;
        }
        m_pPcap->readDatFile(file_path);
    }
}

/**
 * @brief MainWindow::slot_actionExit_triggered  �˵����˳����
 */
void MainWindow::slot_actionExit_triggered()
{
    this->close();
}
/**
 * @brief MainWindow::slot_actionSeting_triggered  ���ñ��沶�񵽱���·��
 */
void MainWindow::slot_actionSeting_triggered()
{
    //ѡ����ץ���ļ�·��
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
 * \brief MainWindow::getPort  ��ȡ�˿ں�
 * \return  true�˿ںŷ�������
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
