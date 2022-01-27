#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
    namespace Ui { class MainWindow; }
QT_END_NAMESPACE

    class MainWindow : public QMainWindow
{
  Q_OBJECT

      public:
               MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

             private:
               void init_device_combobox();

             private slots:
               void on_refresh_btn_clicked();

               void on_browser_btn_clicked();

               void on_certpath_edit_textChanged(const QString &arg1);

               void on_import_btn_clicked();

               void on_gencsr_btn_clicked();

             private:
  Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
