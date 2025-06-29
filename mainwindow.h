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
#include <QMap>
#include <QPair>
extern "C" {
#include <pcap.h>
}

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

// 协议层定义
enum ProtocolLayer {
    LAYER_ETHERNET = 0,
    LAYER_IP,
    LAYER_TRANSPORT,
    LAYER_APPLICATION
};

// 协议字段信息
struct ProtocolField {
    int offset;     // 在数据包中的偏移
    int length;     // 字段长度
    ProtocolLayer layer;  // 所属层
};

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
    QString appProtocol;  // 应用层协议
    QMap<QString, ProtocolField> fields; // 协议字段映射
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

// 扩展的QTreeWidgetItem，存储协议字段信息
class ProtocolTreeItem : public QTreeWidgetItem {
public:
    ProtocolTreeItem(const QStringList &strings) : QTreeWidgetItem(strings) {}
    void setFieldInfo(int offset, int length, ProtocolLayer layer) {
        fieldOffset = offset;
        fieldLength = length;
        fieldLayer = layer;
    }
    int getFieldOffset() const { return fieldOffset; }
    int getFieldLength() const { return fieldLength; }
    ProtocolLayer getFieldLayer() const { return fieldLayer; }
private:
    int fieldOffset = -1;
    int fieldLength = 0;
    ProtocolLayer fieldLayer = LAYER_ETHERNET;
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
    void onProtocolTreeItemClicked(QTreeWidgetItem *item, int column);
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
    int currentPacketIndex = -1;  // 当前选中的数据包索引

    void setupUI();
    void parseAndDisplayPacket(const QByteArray &data, const struct pcap_pkthdr *header);
    void updateProtocolTree(const PacketInfo &info);
    void updateRawDataView(const QByteArray &data, int highlightStart = -1, int highlightLen = 0, ProtocolLayer layer = LAYER_ETHERNET);
    bool filterPacket(const PacketInfo &info);

    // 应用层协议解析
    QString parseApplicationProtocol(const QByteArray &data, int offset, quint16 srcPort, quint16 dstPort, PacketInfo &info);
    void parseHTTP(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent);
    void parseDNS(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent);
    void parseDHCP(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent);

    // 辅助函数
    QString getFriendlyDeviceName(const QString &devName);
    QString ipToString(const uchar *ip);
    QString macToString(const uchar *mac);
};

#endif // MAINWINDOW_H
