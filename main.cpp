#include "Core/mainwindow.h"
#include <QApplication>
#include <QTranslator>




int main(int argc, char **argv)
{
	QApplication a(argc, argv);

    //��װ�����ļ�
    QTranslator t_Translator;
    if(t_Translator.load(a.applicationDirPath()+"/translations/"+qApp->applicationName()+"_zh_CN.qm"))
    {
        a.installTranslator(&t_Translator);
    }

    MainWindow w;
	w.show();
	return a.exec();
}
