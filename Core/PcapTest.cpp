#include "PcapTest.h"
#include <QDebug>
#include <QMessageBox>

#include "TransferSignas.h"

PcapTest::PcapTest(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    //IP 正则表达式
    regExp.setPattern("^((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)$");

    init();
}

/*!
 * @brief 窗口退出事件
 * @param event 退出事件对象
 */
void PcapTest::closeEvent(QCloseEvent *event)
{
    if (Flag)
    {
        QMessageBox::StandardButton res = QMessageBox::warning(this, tr("warning"), tr("in working ,exit?"),
                                                               QMessageBox::Yes | QMessageBox::No);//正在抓包中，是否退出？
        if (res == QMessageBox::StandardButton::Yes)
        {
            pcap->closeCard();
            event->accept();		//接受信息 程序退出
            return;
        }
        event->ignore();		//忽略信号，程序继续运行
    }
}


/*!
 * 初始化界面信息
 */
void PcapTest::init()
{
    Flag = false;

    pcap = new PcapCommon();
    pcap->winSocketInit();

    //获取本机适配器列表，将列表填充在下拉框中
    QVector<_DEVInfo> devInfo(pcap->findAllDev());
    for (int i = 0; i < devInfo.count(); i++)
    {
        ui.Card_ComboBox->addItem(devInfo.at(i).description);
        DeviceList.insert(i, devInfo.at(i));
    }

    //按钮
    //ui.Start_Btn->setEnabled(false);
    connect(ui.Start_Btn, SIGNAL(clicked(bool)), this, SLOT(slot_Airodump_ng_Button()));
    connect(ui.SetInfo_Btn, SIGNAL(clicked(bool)), this, SLOT(slot_SetInfo_Button()));
}

/*!
 * @brief 开始抓包
 */
void PcapTest::slot_Airodump_ng_Button()
{
    if (!Flag)
    {
        // 1打开适配器
        pcap->SetPort(Port);
        const _DEVInfo devinfo = DeviceList.find(ui.Card_ComboBox->currentIndex()).value();
        if (!pcap->openCard(devinfo))
        {
            ui.Prompt_TextEdit->setPlainText("Connection failed...");
            return;
        }

        ui.Prompt_TextEdit->setPlainText("Connection Succeeded...");
        ui.Start_Btn->setText(QString::fromLocal8Bit("End"));
        ui.SetInfo_Btn->hide();
        Flag = true;
    }
    else
    {
        //关闭并停止线程
        pcap->closeCard();

        ui.Prompt_TextEdit->append("Disconnected");

        ui.Start_Btn->setText(QString::fromLocal8Bit("Start"));
        ui.SetInfo_Btn->show();
        Flag = false;
    }
    ui.SetInfo_Btn->setEnabled(Flag);
}

/*!
 * @brief 设置端口号，源IP，目的IP信息
 */
void PcapTest::slot_SetInfo_Button()
{
    pcap->readDatFile();
    ui.Start_Btn->setEnabled(true);
    return;
}
