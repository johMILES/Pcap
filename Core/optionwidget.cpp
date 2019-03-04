#include "optionwidget.h"

#include <QLabel>
#include <QLineEdit>
#include <QGridLayout>
#include <QString>
#include <QDebug>
#include <QMessageBox>

OptionWidget::OptionWidget(QWidget *parent)
    : QDialog(parent)
{
    initView();
}

OptionWidget::~OptionWidget()
{
    delete g_pAdapterCheckBox;
    delete g_pPortLineEdit;
    delete m_pOKBtn;
    delete m_pCloseBtn;
}

/**
 * @brief OptionWidget::initView   ��ʼ������
 */
void OptionWidget::initView()
{
    this->resize(QSize(400,170));

    QGridLayout *pGridLayout = new QGridLayout();

    //������
    QLabel * pAterl_Labed = new QLabel(this);
    pAterl_Labed->setText(QObject::tr("Aterl_l"));
    pAterl_Labed->setMinimumSize(QSize(70, 25));
    pAterl_Labed->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
    pGridLayout->addWidget(pAterl_Labed, 0, 0, 1, 1);

    //������������
    g_pAdapterCheckBox = new QComboBox(this);
    g_pAdapterCheckBox->setMinimumSize(QSize(150,25));
    g_pAdapterCheckBox->setEditable(false);
    pGridLayout->addWidget(g_pAdapterCheckBox, 0, 1, 1, 3);

    //�˿�
    QLabel * pPort_Labed = new QLabel(this);
    pPort_Labed->setText(QObject::tr("Poet_l"));
    pPort_Labed->setMinimumSize(QSize(60, 25));
    pPort_Labed->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
    pGridLayout->addWidget(pPort_Labed, 0, 4, 1, 1);

    //�˿�����
    g_pPortLineEdit = new QLineEdit(this);
    g_pPortLineEdit->setMinimumSize(QSize(100,25));
    g_pPortLineEdit->setAlignment(Qt::AlignCenter|Qt::AlignVCenter);
    pGridLayout->addWidget(g_pPortLineEdit, 0, 5, 1, 1);

    //ȷ����ť
    m_pOKBtn = new QPushButton(this);
    m_pOKBtn->setText(tr("Yes"));
    QObject::connect(m_pOKBtn, SIGNAL(clicked(bool)), this, SLOT(ok_slot()));
    pGridLayout->addWidget(m_pOKBtn, 1, 1, 1, 3);

    //ȡ����ť
    m_pCloseBtn = new QPushButton(this);
    m_pCloseBtn->setText(tr("Cancel"));
    QObject::connect(m_pCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close_slot()));
    pGridLayout->addWidget(m_pCloseBtn, 1, 4, 1, 3);

    this->setLayout(pGridLayout);
}


/**
 * @brief getAdapterindex  ��ȡѡ��������
 * @return
 */
int OptionWidget::getAdapterIndex()
{
    return g_pAdapterCheckBox->currentIndex();
}


/**
 * @brief OptionWidget::getPort   ��ȡ��ǰ���˶˿ں�
 * @return  �˿ں�
 */
int OptionWidget::getPort()
{
    return g_pPortLineEdit->text().toInt();
}


/**
 * @brief OptionWidget::setCheckBox  ���������б������������
 * @param devs  �������б���ϸ��Ϣ
 */
void OptionWidget::setCheckBox(QVector<_DEVInfo> devs)
{
    for (int i = 0; i < devs.count(); i++)
    {
        g_pAdapterCheckBox->addItem(devs.at(i).description);
    }
}


/**
 * @brief OptionWidget::ok_slot   ȷ����ť���
 */
void OptionWidget::ok_slot()
{
    int port = getPort();
    if (port<1 || port>0xFFFF)
    {
        QMessageBox::warning(this, tr("Warning"), tr("Port number error"));
    }
    else
    {
        done(Accepted);
        this->close();
    }
}


/**
 * @brief OptionWidget::close_slot  ����رհ�ť
 */
void OptionWidget::close_slot()
{
    done(Rejected);
    this->close();
}

