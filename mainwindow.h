#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QTableWidget>
#include <QTreeWidget>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QMutex>
#include <QVector>
#include <QString>
#include <QByteArray>
extern "C" {
#include <pcap.h>
}

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

// 数据包结构体
struct PacketInfo {
    QByteArray rawData;
    QString time;
    QString srcMac;
    QString dstMac;
    QString ethType;
    QString srcIp;
    QString dstIp;
    QString protocol;
    QString srcPort;
    QString dstPort;
};

// 抓包线程
class PacketCaptureThread : public QThread {
    Q_OBJECT
public:
    PacketCaptureThread(QObject *parent = nullptr);
    void setDevice(const QString &devName, bool promisc);
    void setFilter(const QString &filterExp);
    void stop();
protected:
    void run() override;
private:
    QString deviceName;
    bool promiscMode = true;
    QString filterExp;
    volatile bool running = true;
    pcap_t *adhandle = nullptr;
    QMutex mutex;
signals:
    void packetCaptured(const QByteArray &data, const struct pcap_pkthdr *header);
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartCapture();
    void onStopCapture();
    void onPacketCaptured(const QByteArray &data, const struct pcap_pkthdr *header);
    void onPacketTableClicked(int row, int column);
    void onFilterChanged();

private:
    Ui::MainWindow *ui;
    QTableWidget *packetTable;
    QTreeWidget *protocolTree;
    QPlainTextEdit *rawDataEdit;
    QComboBox *deviceCombo;
    QComboBox *modeCombo;
    QLineEdit *macFilterEdit;
    QLineEdit *ethTypeFilterEdit;
    QLineEdit *ipFilterEdit;
    QLineEdit *protoFilterEdit;
    QLineEdit *portFilterEdit;
    QPushButton *startBtn;
    QPushButton *stopBtn;

    PacketCaptureThread *captureThread;
    QVector<PacketInfo> packetList;

    void setupUI();
    void parseAndDisplayPacket(const QByteArray &data, const struct pcap_pkthdr *header);
    void updateProtocolTree(const PacketInfo &info);
    void updateRawDataView(const QByteArray &data, int highlightStart = -1, int highlightLen = 0);
    bool filterPacket(const PacketInfo &info);
};

#endif // MAINWINDOW_H
