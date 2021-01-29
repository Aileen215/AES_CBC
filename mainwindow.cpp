#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    testAesCBC(); // AES的CBC加密模式
}

MainWindow::~MainWindow()
{
    delete ui;

    if (m_pMyAesCBC != nullptr)
    {
        delete m_pMyAesCBC;
        m_pMyAesCBC = nullptr;
    }
}

void MainWindow::testAesCBC()
{
    m_pMyAesCBC = new MyAesCBC(16, (unsigned char *)"abc123");

    // 读取要加密的数据
    QFile file("test.txt");
    if (!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this, "warning", "open file failed");
        return;
    }

    QByteArray srcImage = file.readAll();
    int length = srcImage.size();
    file.close();

    // 加密解密的数据
    QByteArray enImage, deImage;

    // 加密
    int i = m_pMyAesCBC->OnAesEncrypt(srcImage, length, enImage); // i = 加密的数据长度
    QFile wfile("encryption.txt");
    if (!wfile.open(QIODevice::WriteOnly))
    {
        QMessageBox::warning(this, "warning", "can't write enImge");
        return;
    }
    wfile.write(enImage); // 写入加密数据
    wfile.close();

    // 解密
    int ii = m_pMyAesCBC->OnAesUncrypt(enImage, i, deImage); // ii = 解密的数据长度
    Q_UNUSED(ii);
    QFile rfile("decode.txt");
    if (!rfile.open(QIODevice::WriteOnly))
    {
        QMessageBox::warning(this, "warning", "can't write deImage");
        return;
    }
    rfile.write(deImage); // 写入解密数据
    rfile.close();
}

