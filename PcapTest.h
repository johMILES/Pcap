#pragma once

#include <QtWidgets/QMainWindow>
#include <QMap>
#include <QRegExp>
#include <QCloseEvent>

#include "ui_PcapTest.h"
#include "PcapCommon.h"
#include "TransferSignas.h"

#include <QTextDocument>


class PcapTest : public QMainWindow
{
	Q_OBJECT

public:
	PcapTest(QWidget *parent = Q_NULLPTR);

	private slots:
	void slot_Airodump_ng_Button();
	void slot_SetInfo_Button();

protected:
	void closeEvent(QCloseEvent *event);

private:
	Ui::PcapTestClass ui;

	TransferSignas *transferSignas;
	PcapCommon *pcap;
	QMap<int, _DEVInfo> DeviceList;

	//端口、源-目的地IP
	u_short Port;
	QString Source_IP;
	QString Destination_IP;

	bool Flag;	//是否正在抓包标志

	//IP 正则表达式
	QRegExp regExp;

	void init();

};
