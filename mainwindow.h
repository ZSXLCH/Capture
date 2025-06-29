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
    QString info;         // 信息列，显示数据包详细信息
    int originalIndex;    // 原始索引，用于过滤后保持序号
    QMap<QString, ProtocolField> fields; // 协议字段映射，用于高亮
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

// 扩展的QTreeWidgetItem，存储协议字段信息以便高亮
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
    PacketCaptureThread *captureThread;
    QVector<PacketInfo> packetList;
    QMap<int, int> rowToPacketIndex;  // 表格行号到数据包索引的映射
    int currentPacketIndex = -1;  // 当前在表格中选中的数据包索引

    // UI初始化和更新
    void setupUI();
    void updateProtocolTree(const PacketInfo &info);
    void updateRawDataView(const QByteArray &data, int highlightStart = -1, int highlightLen = 0);

    // --- 协议解析核心函数 ---
    void parseAndDisplayPacket(const QByteArray &data);

    // 各层协议解析函数
    int parseEthernet(const QByteArray &data, PacketInfo &info, ProtocolTreeItem *parent);
    int parseArp(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent);
    int parseIpV4(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent);
    int parseIpV6(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent);
    int parseIcmp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent);
    int parseTcp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent);
    int parseUdp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent);

    // 应用层协议解析
    void parseApplicationLayer(const QByteArray &data, int offset, int len, quint16 srcPort, quint16 dstPort, PacketInfo &info, ProtocolTreeItem *parent);
    void parseHTTP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);
    void parseDNS(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);
    void parseDHCP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);
    void parseDhcpOptions(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);

    // --- 辅助函数 ---
    bool filterPacket(const PacketInfo &info);
    QString getFriendlyDeviceName(const QString &devName);
    QString ipToString(const uchar *ip);
    QString ipv6ToString(const uchar *ipv6);
    QString macToString(const uchar *mac);
    QString parseDnsName(const QByteArray &data, int &offset, int baseOffset);
};

#endif // MAINWINDOW_H
