#include "mainwindow.h"

#include <QApplication>

#include <openssl/crypto.h>

int main(int argc, char *argv[])
{
  fprintf(stdout, "openssl Ver: %s\n", OpenSSL_version(0));
  QApplication a(argc, argv);
  MainWindow w;
  w.show();
  return a.exec();
}
