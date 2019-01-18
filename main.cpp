#include "Core/PcapTest.h"
#include <QApplication>
#include <QTranslator>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);

    //安装翻译文件
    QTranslator t_Translator;
    if(t_Translator.load(a.applicationDirPath()+"/translations/"+qApp->applicationName()+"_zh_CN.qm"))
    {
        a.installTranslator(&t_Translator);
    }

	PcapTest w;
	w.show();
	return a.exec();
}
