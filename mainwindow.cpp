#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QClipboard>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>

#include <openssl/gmskf.h>
#include <openssl/err.h>

QStringList enum_device();
int gen_csr(unsigned char *cn, HCONTAINER hct, BYTE *x, BYTE *y, char* csr);

QMap<ULONG, QString> errcode = {
    {SAR_OK, "成功"},
    {SAR_FAIL, "失败"},
    {SAR_UNKNOWNERR, "异常错误"},
    {SAR_NOTSUPPORTYETERR, "不支持的服务"},
    {SAR_FILEERR, "文件操作错误"},
    {SAR_INVALIDHANDLEERR, "无效的句柄"},
    {SAR_INVALIDPARAMERR, "无效的参数"},
    {SAR_READFILEERR, "读文件错误"},
    {SAR_WRITEFILEERR, "写文件错误"},
    {SAR_NAMELENERR, "名称长度错误"},
    {SAR_KEYUSAGEERR, "密钥用途错误"},
    {SAR_MODULUSLENERR, "模的长度错误"},
    {SAR_NOTINITIALIZEERR, "未初始化"},
    {SAR_OBJERR, "对象错误"},
    {SAR_MEMORYERR, "内存错误"},
    {SAR_TIMEOUTERR, "超时"},
    {SAR_INDATALENERR, "输入数据长度错误"},
    {SAR_INDATAERR, "输入数据错误"},
    {SAR_GENRANDERR, "生成随机数错误"},
    {SAR_HASHOBJERR, " HASH对象错误"},
    {SAR_HASHERR, " HASH运算错误"},
    {SAR_GENRSAKEYERR, "产生RSA密钥错误"},
    {SAR_RSAMODULUSLENERR, " RSA密钥模长错误"},
    {SAR_CSPIMPRTPUBKEYERR, " CSP服务导入公钥错误"},
    {SAR_RSAENCERR, " RSA加密错误"},
    {SAR_RSADECERR, " RSA解密错误"},
    {SAR_HASHNOTEQUALERR, " HASH值不相等"},
    {SAR_KEYNOTFOUNTERR, "未发现密钥"},
    {SAR_CERTNOTFOUNTERR, "未发现证书"},
    {SAR_NOTEXPORTERR, "对象未导出"},
    {SAR_DECRYPTPADERR, "解密时做补丁错误"},
    {SAR_MACLENERR, " MAC长度错误"},
    {SAR_BUFFER_TOO_SMALL, "缓冲区不足"},
    {SAR_KEYINFOTYPEERR, "密钥类型错误"},
    {SAR_NOT_EVENTERR, "无事件错误"},
    {SAR_DEVICE_REMOVED, "设备已移除"},
    {SAR_PIN_INCORRECT, " PIN错误"},
    {SAR_PIN_LOCKED, " PIN锁死"},
    {SAR_PIN_INVALID, " PIN无效"},
    {SAR_PIN_LEN_RANGE, " PIN长度错误"},
    {SAR_USER_ALREADY_LOGGED_IN, "用户已经登录"},
    {SAR_USER_PIN_NOT_INITIALIZED, "没有初始化用户口令"},
    {SAR_USER_TYPE_INVALID, " PIN类型错误"},
    {SAR_APPLICATION_NAME_INVALID, "应用名称无效"},
    {SAR_APPLICATION_EXISTS, "应用已经存在"},
    {SAR_USER_NOT_LOGGED_IN, "用户没有登录"},
    {SAR_APPLICATION_NOT_EXISTS, "应用不存在"},
    {SAR_FILE_ALREADY_EXIST, "文件已经存在"},
    {SAR_NO_ROOM, "存储空间不足"},
    {SAR_FILE_NOT_EXIST, "文件不存在"},
    {SAR_REACH_MAX_CONTAINER_COUNT, "已达到最大可管理容器数"},
//    {SAR_SECURITY_INVALID, "安全状态不满足"},
//    {SAR_OFFSET_VOER_FILE, "指针移到超过文件长度"},
//    {SAR_CONTAINER_NOT_FOUND, "容器不存在"},
//    {SAR_CONTAINER_EXIST, "容器已存在"},
//    {SAR_AUTH_LOCKED, "设备认证锁定"},
//    {SAR_ECCENCERR, " ECC加密错误"},
};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
  int ret = SKF_LoadLibrary(LPSTR("/usr/local/lib/libgm3000.1.0.dylib"), NULL);
  if (ret != SAR_OK) {
      printf("load skf failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
      exit(1);
  }
  ui->setupUi(this);
  ui->csr_name->setPlaceholderText("填写csr名称");
  init_device_combobox();
}

MainWindow::~MainWindow() { 
  SKF_UnloadLibrary(); 
  delete ui; 
}

void MainWindow::init_device_combobox() {
  QList<QString> devList = enum_device();
  QStringList list(devList);
  ui->device_list->addItems(list);
}

void MainWindow::on_refresh_btn_clicked() { init_device_combobox(); }

void MainWindow::on_browser_btn_clicked() {
  QString fileName = QFileDialog::getOpenFileName(
      this, tr("请选择证书"), "./", tr("Certificate (*.cer *.pem *.p12)"));
  ui->certpath_edit->setText(fileName);
}

void MainWindow::on_certpath_edit_textChanged(const QString &path) {
  ui->certpath_edit->setText(path);
}

QStringList enum_device() {
  QStringList list;
  ULONG ulSize = 0;
  ULONG ulRslt = SAR_OK;
  bool present = true;

  LPSTR devNames = nullptr;
  ulRslt = SKF_EnumDev(present, devNames, &ulSize);
  if (ulRslt || !ulSize) {
    printf("SKF_EnumDev ret: %x\n", ulRslt);
    return list;
  }

  LPSTR tmp = devNames = (LPSTR)calloc(ulSize, sizeof(char));
  ulRslt = SKF_EnumDev(present, devNames, &ulSize);
  if (ulRslt) {
    printf("SKF_EnumDev failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    free(devNames);
    return list;
  }

  // must loop the whole devs by ulSize
  for (ULONG i = 0; i < ulSize - 1; i++) {
    if ('\0' == tmp[i]) {
      std::string n = (char*)devNames;
      list.append(QString::fromStdString(n));
      devNames += i + 1;
    }
  }

  free(tmp);
  return list;
}

void MainWindow::on_import_btn_clicked() {
  QMessageBox msgBox;
  msgBox.setDefaultButton(QMessageBox::Ok);
  msgBox.setIcon(QMessageBox::Warning);
  QString currentDev = ui->device_list->currentText();
  HANDLE hdev = nullptr;
  HAPPLICATION hApp = nullptr;
  QString defaultApp("VHSMAPP");
  QString pin = ui->pin_edit->text();
  ULONG retry = 0;
  HCONTAINER hCt = nullptr;
  QString defaultCT("vhsm-container");
  ULONG uRet = 0;
  QString filename = ui->certpath_edit->text();
  QFile certfile(filename);
  certfile.open(QFile::ReadOnly);

  QByteArray certdata = certfile.readAll();
  if (certdata.size() == 0) {
    msgBox.setText("证书数据为空");
    msgBox.exec();
    goto err;
  }

  uRet = SKF_ConnectDev((LPSTR)currentDev.toLocal8Bit().data(), &hdev);
  if (uRet != SAR_OK) {
    msgBox.setText("未连接到指定的设备：" + currentDev + ", " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = SKF_OpenApplication(hdev, (LPSTR)defaultApp.toLocal8Bit().data(), &hApp);
  if (uRet != SAR_OK) {
    msgBox.setText("打开默认应用程序：VHSMAPP, " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)pin.toLocal8Bit().data(), &retry);
  if (uRet != SAR_OK) {
    msgBox.setText(QString::asprintf("口令验证失败, %s, 剩余重试次数: %d",
                                     errcode[uRet].toStdString().data(),
                                     retry));
    msgBox.exec();
    goto err;
  }

  uRet = SKF_OpenContainer(hApp, (LPSTR)defaultCT.toLocal8Bit().data(), &hCt);
  if (uRet != SAR_OK) {
    msgBox.setText("打开默认容器：vhsm-container, " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = SKF_ImportCertificate(hCt, true, (BYTE *)certdata.data(),
                               certdata.size());
  if (uRet != SAR_OK) {
    msgBox.setText("导入失败, " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  msgBox.setIcon(QMessageBox::NoIcon);
  msgBox.setText("导入成功");
  msgBox.exec();

err:
  if (hCt)
    SKF_CloseContainer(hCt);
  if (hApp)
    SKF_CloseApplication(hApp);
  if (hdev)
    SKF_DisConnectDev(hdev);
}

void MainWindow::on_gencsr_btn_clicked() {
  QPushButton *copyBtn, *saveBtn;
  QMessageBox msgBox;
  msgBox.setDefaultButton(QMessageBox::Ok);
  msgBox.setIcon(QMessageBox::Warning);
  QString currentDev = ui->device_list->currentText();
  HANDLE hdev = nullptr;
  ULONG uRet = 0;
  HAPPLICATION hApp = nullptr;
  QString defaultApp("VHSMAPP");
  QString csrName = ui->csr_name->text();
  QString pin = ui->pin_edit->text();
  ULONG retry = 0;
  HCONTAINER hCt = nullptr;
  QString defaultCT("mpki-test");
  ECCPUBLICKEYBLOB pBlob;
  memset(&pBlob, 0, sizeof(ECCPUBLICKEYBLOB));
  char csr[1024] = {0};

  if (csrName == "") {
    msgBox.setText("请填写名称");
    msgBox.exec();
    goto err;
  }

  uRet = SKF_ConnectDev((LPSTR)currentDev.toLocal8Bit().data(), &hdev);
  if (uRet != SAR_OK) {
    msgBox.setText("未连接到指定的设备：" + currentDev + ", " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = SKF_OpenApplication(hdev, (LPSTR)defaultApp.toLocal8Bit().data(), &hApp);
  if (uRet != SAR_OK) {
    msgBox.setText("打开默认应用程序：VHSMAPP, " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)pin.toLocal8Bit().data(), &retry);
  if (uRet != SAR_OK) {
    msgBox.setText(QString::asprintf("口令验证失败, %s, 剩余重试次数: %d",
                                     errcode[uRet].toStdString().data(),
                                     retry));
    msgBox.exec();
    goto err;
  }

  uRet = SKF_OpenContainer(hApp, (LPSTR)defaultCT.toLocal8Bit().data(), &hCt);
  if (uRet != SAR_OK) {
    msgBox.setText("打开默认容器：vhsm-container, " + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = SKF_GenECCKeyPair(hCt, SGD_SM2_1, &pBlob);
  if (uRet != SAR_OK) {
    msgBox.setText("生成公私钥对失败，" + errcode[uRet]);
    msgBox.exec();
    goto err;
  }

  uRet = gen_csr((BYTE *)ui->csr_name->text().toLocal8Bit().data(), hCt,
                 pBlob.XCoordinate + 32, pBlob.YCoordinate + 32, &csr[0]);
  if (uRet == 0) {
    msgBox.setText("CSR生成失败");
    msgBox.exec();
    goto err;
  }

  copyBtn = msgBox.addButton(tr("复制"), QMessageBox::ActionRole);
  saveBtn = msgBox.addButton(tr("保存"), QMessageBox::ActionRole);
  msgBox.setIcon(QMessageBox::Information);
  msgBox.setText(QString(&csr[0]));
  msgBox.exec();

  if (msgBox.clickedButton() == copyBtn) {
    QClipboard *clip = QApplication::clipboard();
    clip->setText(msgBox.text());
  } else if (msgBox.clickedButton() == saveBtn) {
    QString fileName = QFileDialog::getSaveFileName(this, "Save");
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QFile::Text)) {
      QMessageBox::warning(this, "Warning",
                           "Cannot save file: " + file.errorString());
      return;
    }
    setWindowTitle(fileName);
    QTextStream out(&file);
    QString text = msgBox.text();
    out << text;
    file.close();
  }

err:
  if (hCt)
    SKF_CloseContainer(hCt);
  if (hApp)
    SKF_CloseApplication(hApp);
  if (hdev)
    SKF_DisConnectDev(hdev);
}
