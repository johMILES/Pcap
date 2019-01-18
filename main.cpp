#include "PcapTest.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	PcapTest w;
	w.show();
	return a.exec();
}
