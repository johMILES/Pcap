#ifndef OPTIONWIDGET_H
#define OPTIONWIDGET_H

#include <QDialog>
#include <QVector>
#include <QComboBox>
#include <QPushButton>

#include "Public.h"


class OptionWidget : public QDialog
{
    Q_OBJECT
public:
    explicit OptionWidget(QWidget *parent = 0);
    ~OptionWidget();

public slots:
    void ok_slot();
    void close_slot();

public:
    int getAdapterIndex();
    int getPort();
    void setCheckBox(QVector<_DEVInfo> devsInfo);

private:
    void initView();
    QComboBox *g_pAdapterCheckBox;
    QLineEdit *g_pPortLineEdit;
    QPushButton *m_pOKBtn;
    QPushButton *m_pCloseBtn;


};

#endif // OPTIONWIDGET_H
