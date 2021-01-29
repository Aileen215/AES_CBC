#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QObject>
#include <QFile>
#include <QByteArray>
#include <QImage>
#include <QImageReader>
#include <QMessageBox>
#include "myaescbc.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void testAesCBC();

private:
    Ui::MainWindow *ui;

    MyAesCBC *m_pMyAesCBC = nullptr;
};
#endif // MAINWINDOW_H
