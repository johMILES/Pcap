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

    m_pPcap = NULL;

    initWidget();
}

MainWindow::~MainWindow()
{
    delete ui;
}

/*!
 * ��ʼ��������Ϣ
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
}

/*!
 * @brief ��ʼ��Pcap���
 */
void MainWindow::initPcap()
{
    if(m_pPcap == NULL)
    {
        m_pPcap = new PcapCommon();
        m_pPcap->winSocketInit();

        //��ȡ�����������б������б��������������
        QVector<_DEVInfo> devInfo(m_pPcap->findAllDev());
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
 * @brief �����˳��¼�
 * @param event �˳��¼�����
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
            event->accept();		//������Ϣ �����˳�
            return;
        }
        event->ignore();		//�����źţ������������
    }
}

/*!
 * @brief ��ʼץ��
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
        m_pPcap->SetPort(m_Port);
        const _DEVInfo devinfo = m_DeviceList.find(ui->Card_ComboBox->currentIndex()).value();
        if (!m_pPcap->openCard(devinfo))
        {
            ui->Prompt_TextEdit->setPlainText("Connection failed...");
            return;
        }

        ui->Prompt_TextEdit->setPlainText("Connection Succeeded...");
        ui->Start_Btn->setText(QString::fromLocal8Bit("End"));
        m_bFlag = true;
    }
    else
    {
        //�رղ�ֹͣ�߳�
        m_pPcap->closeCard();
        ui->Prompt_TextEdit->append("Disconnected");
        ui->Start_Btn->setText(QString::fromLocal8Bit("Start"));
        m_bFlag = false;
    }
}

/*!
 * @brief ��ȡ���������ļ�
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