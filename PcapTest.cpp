#include "PcapTest.h"

#include <QDebug>
#include <QMessageBox>

#include "TransferSignas.h"


PcapTest::PcapTest(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	//IP ������ʽ
	regExp.setPattern("^((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)$");

	init();

}

void PcapTest::closeEvent(QCloseEvent *event)
{
	if (Flag)
	{
		QMessageBox::StandardButton res = QMessageBox::warning(this, "warning", QString::fromLocal8Bit("����ץ���У��Ƿ��˳���"), QMessageBox::Yes | QMessageBox::No);
		if (res == QMessageBox::StandardButton::Yes)
		{
			pcap->closeCard();
			event->accept();		//������Ϣ �����˳�
			return;
		}
		event->ignore();		//�����źţ������������
	}
}


/*!
 * ��ʼ��������Ϣ
 */
void PcapTest::init()
{
	Flag = false;

	pcap = new PcapCommon();
	pcap->winSocketInit();

	//��ȡ�����������б����б��������������
	QVector<_DEVInfo> devInfo(pcap->findAllDev());
	for (int i = 0; i < devInfo.count(); i++)
	{
		ui.Card_ComboBox->addItem(devInfo.at(i).description);
		DeviceList.insert(i, devInfo.at(i));
	}

	ui.Port_LineEdit->setText("1024");
	ui.Source_LineEdit->setText("127.0.0.1");
	ui.Destination_LineEdit->setText("127.0.0.1");

	//IP ������ʽ
	QRegExpValidator *m_IPValidator = new QRegExpValidator(regExp, this);
	ui.Source_LineEdit->setValidator(m_IPValidator);
	ui.Destination_LineEdit->setValidator(m_IPValidator);

	//��ť
	//ui.Start_Btn->setEnabled(false);
	connect(ui.Start_Btn, SIGNAL(clicked(bool)), this, SLOT(slot_Airodump_ng_Button()));
	connect(ui.SetInfo_Btn, SIGNAL(clicked(bool)), this, SLOT(slot_SetInfo_Button()));

}


//��ʼץ��
void PcapTest::slot_Airodump_ng_Button()
{
	if (!Flag)
	{
		// 1��������
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
		//�رղ�ֹͣ�߳�
		pcap->closeCard();

		ui.Prompt_TextEdit->append("Disconnected");

		ui.Start_Btn->setText(QString::fromLocal8Bit("Start"));
		ui.SetInfo_Btn->show();
		Flag = false;
	}
	ui.SetInfo_Btn->setEnabled(Flag);
}

//���ö˿ںţ�ԴIP��Ŀ��IP��Ϣ
void PcapTest::slot_SetInfo_Button()
{

	pcap->readDatFile();


	ui.Start_Btn->setEnabled(true);

	return;
	int t_Int;

	//�˿ں�
	t_Int = ui.Port_LineEdit->text().toInt();
	if (t_Int<1 || t_Int>0xFFFF)
	{
		QMessageBox::warning(this, "Warning", "�˿ں����÷�ΧӦ��0-65535");
		return;
	}
	else
	{
		Port = t_Int;
	}

	//Դ��ַ
	if (!regExp.exactMatch(ui.Source_LineEdit->text()))
	{
		QMessageBox::warning(this, "Warning", "Source IP Address Error");
		return;
	}
	else
	{
		Source_IP = ui.Source_LineEdit->text();
	}

	//Ŀ�ĵ�ַ
	if (!regExp.exactMatch(ui.Destination_LineEdit->text()))
	{
		QMessageBox::warning(this, "Warning", "Destination IP Address Error");
		return;
	}
	else
	{
		Destination_IP = ui.Destination_LineEdit->text();
	}

	ui.Start_Btn->setEnabled(true);
}




