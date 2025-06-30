#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QResizeEvent>
#include <QVector>
#include <QMap>
#include "PacketInfo/packetinfo.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class PacketCaptureThread;
class ProtocolParser;
class QTreeWidgetItem;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent *event) override;

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
    ProtocolParser *protocolParser;
    QVector<PacketInfo> packetList;
    QMap<int, int> rowToPacketIndex;  // 表格行号到数据包索引的映射
    int currentPacketIndex = -1;      // 当前在表格中选中的数据包索引

    // UI初始化和更新
    void updateProtocolTree(const PacketInfo &info);
    void updateRawDataView(const QByteArray &data, int highlightStart = -1, int highlightLen = 0);
    void parseAndDisplayPacket(const QByteArray &data);

    // 辅助函数
    bool filterPacket(const PacketInfo &info);
    QString getFriendlyDeviceName(const QString &devName);
};

#endif // MAINWINDOW_H
