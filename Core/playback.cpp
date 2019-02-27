
#include <QApplication>
#include <QFile>
#include <QDataStream>
#include <QFileDialog>
#include <QGridLayout>
#include <QLabel>
#include <QDebug>

#include "playback.h"
#include "PcapCommon.h"
#include "pcap.h"
#include "Base/messaging.h"

Playback::Playback(QWidget *parent)
    : QWidget(parent)
{
    initWidget();
    this->resize(300,150);
}



Playback::~Playback()
{

}


/**
 * @brief Playback::initWidget
 */
void Playback::initWidget()
{
    QGridLayout *pGridLayout = new QGridLayout();

    //������
    QLabel * pAterl_Labed = new QLabel(this);
    pAterl_Labed->setText(QObject::tr(""));
    pAterl_Labed->setMinimumSize(QSize(70, 25));
    pAterl_Labed->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
    pGridLayout->addWidget(pAterl_Labed, 0, 0, 1, 1);

    //������������
    m_pAdapterComboBox = new QComboBox(this);
    m_pAdapterComboBox->setMinimumSize(QSize(150,25));
    m_pAdapterComboBox->setEditable(false);
    pGridLayout->addWidget(m_pAdapterComboBox, 0, 1, 1, 3);


    //ȷ����ť
    m_pFileBtn = new QPushButton(this);
    m_pFileBtn->setText(tr("Start Playback"));
    QObject::connect(m_pFileBtn, SIGNAL(clicked(bool)), this, SLOT(fileBtn_slot()));
    pGridLayout->addWidget(m_pFileBtn, 1, 1, 1, 3);
    m_pFileBtn->setEnabled(false);

    //ȡ����ť
    m_pCancelPlayback = new QPushButton(this);
    m_pCancelPlayback->setText(tr("Cancel Playback"));
    QObject::connect(m_pCancelPlayback, SIGNAL(clicked(bool)), this, SLOT(cancelPlayback_slot()));
    pGridLayout->addWidget(m_pCancelPlayback, 1, 4, 1, 3);

    this->setLayout(pGridLayout);
}

/**
 * @brief Playback::fileBtn_slot
 */
void Playback::fileBtn_slot()
{
    m_pFileBtn->setEnabled(false);
    StartPlayback(m_csFilePath);
}


/**
 * @brief Playback::cancelPlayback_slot
 */
void Playback::cancelPlayback_slot()
{
    m_pFileBtn->setEnabled(true);
    this->hide();
}


/**
 * @brief Playback::setFilePath
 * @param path
 */
void Playback::setFilePath(QString path)
{
    m_csFilePath = path;
    m_pFileBtn->setEnabled(true);
    m_pCancelPlayback->setEnabled(false);
}


/**
 * @brief OptionWidget::setCheckBox  ���������б������������
 * @param devs  �������б���ϸ��Ϣ
 */
void Playback::setCheckBox(QVector<_DEVInfo> devs)
{
    for (int i = 0; i < devs.count(); i++)
    {
        m_pAdapterComboBox->addItem(devs.at(i).description);
    }
    m_DevInfo = devs;
}


/**
 * @brief PcapCommon::StartPlayback  ��ȡ������ļ�
 * @param path  ��ȡ�ļ�·��
 */
void Playback::StartPlayback(QString path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return;

    PcapCommon::getInstance()->openCard(m_DevInfo.at(m_pAdapterComboBox->currentIndex()));

    QDataStream out(&file);

    double t_d1 = 0,t_d2 = 0;
    LARGE_INTEGER t_frequency;
    LARGE_INTEGER t_L1,t_L2;

    QueryPerformanceFrequency(&t_frequency);    //��ȡʱ��Ƶ��

    //��ȡ��ǰʱ��
    QueryPerformanceCounter(&t_L1);
    t_d1 = (double)t_L1.QuadPart/t_frequency.QuadPart;

    static double TimeDifference = 0;   //����ʱ��
    TimeDifference = 0;

    while (!out.atEnd())
    {
        QByteArray src_ip;
        QByteArray dst_ip;
        QByteArray payload;

        unsigned short SrcPort;
        unsigned short DstPort;         //�շ�Port
        QByteArray timeDif;

        //TODO: ������ʱ������ռ�ýϴ��CPU��Դ
        do{
            QueryPerformanceCounter(&t_L2);
            t_d2 = (double)t_L2.QuadPart/t_frequency.QuadPart;
        } while(t_d2-t_d1 <= TimeDifference);

        t_d1 = t_d2;

        out >> src_ip >> dst_ip >> SrcPort >> DstPort >> timeDif >> payload;
        TimeDifference = timeDif.toDouble();

        qDebug() << src_ip << dst_ip << SrcPort << DstPort << TimeDifference << payload;

//        char * data = { 0 };
//        data = (char*)malloc(payload.length());
//        memset(data, 0, payload.length());

        //�ط�
//        PcapCommon::getInstance()->sendData(src_ip, dst_ip, payload, SrcPort, DstPort);

//        data = payload.data();
//        data = NULL;
//        free(data);
    }

    //�طŽ���
    file.close();
    Messaging::getInstance()->messageMenubar(tr("End of playback"));
    this->hide();
}

