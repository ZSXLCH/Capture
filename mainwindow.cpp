#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QMessageBox>
#include <QDebug>
#include <QScrollBar>
#include <QTextCharFormat>
#include <QBrush>
#include <QColor>
#include <QTextCursor>
#include <QTextBlock>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QByteArray>
#include <QMutexLocker>
#include <QTimer>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QApplication>
#include <QTableWidgetItem>
#include <QTreeWidgetItem>
#include <QVector>
#include <QMap>
#include <QSet>
#include <QTextStream>
#include <QRegularExpression>
#include <QTextDocument>
#include <QTextBlockFormat>
extern "C" {
#include <pcap.h>
}

// ------------------- PacketCaptureThread 实现 -------------------
PacketCaptureThread::PacketCaptureThread(QObject *parent) : QThread(parent) {}

void PacketCaptureThread::setDevice(const QString &devName, bool promisc) {
    QMutexLocker locker(&mutex);
    deviceName = devName;
    promiscMode = promisc;
}

void PacketCaptureThread::setFilter(const QString &filterExp_) {
    QMutexLocker locker(&mutex);
    filterExp = filterExp_;
}

void PacketCaptureThread::stop() {
    running = false;
}

void PacketCaptureThread::run() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    QByteArray devNameUtf8 = deviceName.toUtf8();
    adhandle = pcap_open_live(devNameUtf8.constData(), 65536, promiscMode ? 1 : 0, 1000, errbuf);
    if (!adhandle) return;
    if (!filterExp.isEmpty()) {
        struct bpf_program fcode;
        if (pcap_compile(adhandle, &fcode, filterExp.toUtf8().constData(), 1, 0xffffff) < 0) {
            pcap_close(adhandle);
            return;
        }
        pcap_setfilter(adhandle, &fcode);
    }
    running = true;
    while (running) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(adhandle, &header, &pkt_data);
        if (res == 1) {
            emit packetCaptured(QByteArray((const char*)pkt_data, header->caplen), header);
        } else if (res == 0) {
            msleep(10);
        } else {
            break;
        }
    }
    pcap_close(adhandle);
}

// ------------------- MainWindow 实现 -------------------
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , captureThread(nullptr)
{
    ui->setupUi(this);

    // 设备列表 - 使用友好名称
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            QString friendlyName = getFriendlyDeviceName(QString::fromUtf8(d->name));
            if (d->description) {
                friendlyName = QString::fromUtf8(d->description);
            }
            ui->deviceCombo->addItem(friendlyName, QString::fromUtf8(d->name));
        }
        pcap_freealldevs(alldevs);
    }
    ui->modeCombo->addItem("混杂模式");
    ui->modeCombo->addItem("直接模式");

    connect(ui->startBtn, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(ui->stopBtn, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(ui->packetTable, &QTableWidget::cellClicked, this, &MainWindow::onPacketTableClicked);
    connect(ui->protocolTree, &QTreeWidget::itemClicked, this, &MainWindow::onProtocolTreeItemClicked);
    connect(ui->macFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->ethTypeFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->ipFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->protoFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->portFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    ui->stopBtn->setEnabled(false);

    // 设置表头可调整大小，而不是自适应
    ui->packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    ui->packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 设置表格样式
    ui->packetTable->setShowGrid(true);
    ui->packetTable->setGridStyle(Qt::SolidLine);
    ui->packetTable->setSelectionBehavior(QAbstractItemView::SelectRows); // 整行选择
    ui->packetTable->setSelectionMode(QAbstractItemView::SingleSelection); // 单选模式
    
    // 设置选中行背景色为灰色
    QPalette palette = ui->packetTable->palette();
    palette.setColor(QPalette::Highlight, QColor(128, 128, 128)); // 选中行背景色为灰色
    palette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
    ui->packetTable->setPalette(palette);

    // 设置合理的默认列宽
    ui->packetTable->setColumnWidth(0, 60);   // 序号
    ui->packetTable->setColumnWidth(1, 100);  // 时间
    ui->packetTable->setColumnWidth(2, 150);  // 源MAC
    ui->packetTable->setColumnWidth(3, 150);  // 目的MAC
    ui->packetTable->setColumnWidth(4, 80);   // 类型
    ui->packetTable->setColumnWidth(5, 120);  // 源IP
    ui->packetTable->setColumnWidth(6, 120);  // 目的IP
    ui->packetTable->setColumnWidth(7, 80);   // 协议
    ui->packetTable->setColumnWidth(8, 60);   // 长度
    ui->packetTable->setColumnWidth(9, 300);  // 信息

    // 设置原始数据视图字体
    QFont monoFont("Consolas");
    monoFont.setStyleHint(QFont::Monospace);
    ui->rawDataEdit->setFont(monoFont);

    // 启动时最大化窗口
    this->showMaximized();
}

MainWindow::~MainWindow() {
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
    }
    delete ui;
}

QString MainWindow::getFriendlyDeviceName(const QString &devName) {
    // 尝试提取更友好的设备名称
    if (devName.contains("\\Device\\NPF_")) {
        QString name = devName.mid(devName.lastIndexOf("\\Device\\NPF_") + 12);
        return name;
    }
    return devName;
}

void MainWindow::onStartCapture() {
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
        captureThread = nullptr;
    }
    packetList.clear();
    rowToPacketIndex.clear();  // 清空映射表
    ui->packetTable->setRowCount(0);
    ui->protocolTree->clear();
    ui->rawDataEdit->clear();

    QString dev = ui->deviceCombo->currentData().toString();
    if (dev.isEmpty()) {
        dev = ui->deviceCombo->currentText();
    }

    bool promisc = (ui->modeCombo->currentIndex() == 0);
    captureThread = new PacketCaptureThread(this);
    captureThread->setDevice(dev, promisc);
    connect(captureThread, &PacketCaptureThread::packetCaptured, this, &MainWindow::onPacketCaptured);
    captureThread->start();
    ui->startBtn->setEnabled(false);
    ui->stopBtn->setEnabled(true);
    ui->deviceCombo->setEnabled(false); // 禁用网卡选择
    ui->modeCombo->setEnabled(false);   // 禁用捕获模式选择
}

void MainWindow::onStopCapture() {
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
        captureThread = nullptr;
    }
    ui->startBtn->setEnabled(true);
    ui->stopBtn->setEnabled(false);
    ui->deviceCombo->setEnabled(true); // 恢复网卡选择
    ui->modeCombo->setEnabled(true);   // 恢复捕获模式选择
}

void MainWindow::onPacketCaptured(const QByteArray &data, const struct pcap_pkthdr *header) {
    parseAndDisplayPacket(data);
}

// 将MAC地址转换为字符串格式
QString MainWindow::macToString(const uchar *mac) {
    return QString("%1-%2-%3-%4-%5-%6")
    .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0')).toUpper();
}

// 将IPv4地址转换为字符串格式
QString MainWindow::ipToString(const uchar *ip) {
    return QString("%1.%2.%3.%4").arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
}

// 将IPv6地址转换为字符串格式
QString MainWindow::ipv6ToString(const uchar *ipv6) {
    QString result;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) result += ":";
        result += QString("%1").arg((ipv6[i] << 8) | ipv6[i + 1], 4, 16, QChar('0'));
    }
    return result;
}

// 解析并显示数据包
void MainWindow::parseAndDisplayPacket(const QByteArray &data) {
    PacketInfo info;
    info.rawData = data;
    info.time = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    info.originalIndex = packetList.size() + 1;  // 设置原始序号（从1开始）

    // 解析以太网层
    int offset = parseEthernet(data, info, nullptr);
    if (offset < 0) return;

    // 应用过滤器
    if (!filterPacket(info)) {
        // 即使不显示，也要添加到列表中
        packetList.append(info);
        return;
    }

    // 添加到列表
    packetList.append(info);

    // 添加到表格
    QString displayProtocol = info.protocol;
    if (!info.appProtocol.isEmpty()) {
        displayProtocol = info.appProtocol;
    }

    int row = ui->packetTable->rowCount();
    ui->packetTable->insertRow(row);

    // 记录行号和数据包索引的映射关系
    rowToPacketIndex[row] = packetList.size() - 1;

    ui->packetTable->setItem(row, 0, new QTableWidgetItem(QString::number(info.originalIndex)));
    ui->packetTable->setItem(row, 1, new QTableWidgetItem(info.time));
    ui->packetTable->setItem(row, 2, new QTableWidgetItem(info.srcMac));
    ui->packetTable->setItem(row, 3, new QTableWidgetItem(info.dstMac));
    ui->packetTable->setItem(row, 4, new QTableWidgetItem(info.ethType));
    ui->packetTable->setItem(row, 5, new QTableWidgetItem(info.srcIp));
    ui->packetTable->setItem(row, 6, new QTableWidgetItem(info.dstIp));
    ui->packetTable->setItem(row, 7, new QTableWidgetItem(displayProtocol));
    ui->packetTable->setItem(row, 8, new QTableWidgetItem(QString::number(data.size())));
    ui->packetTable->setItem(row, 9, new QTableWidgetItem(info.info));
}

// 解析以太网帧头部
int MainWindow::parseEthernet(const QByteArray &data, PacketInfo &info, ProtocolTreeItem *parent) {
    // 以太网帧头部最少14字节
    if (data.size() < 14) return -1;

    const uchar *d = (const uchar*)data.constData();

    // 解析目的MAC地址
    info.dstMac = macToString(d);
    // 解析源MAC地址
    info.srcMac = macToString(d + 6);
    // 解析以太网类型/长度字段
    quint16 ethType = (d[12] << 8) | d[13];
    info.ethType = QString("0x%1").arg(ethType, 4, 16, QChar('0')).toUpper();

    // 存储以太网层字段位置
    info.fields["eth_header"] = {0, 14, LAYER_ETHERNET};
    info.fields["eth_dst"] = {0, 6, LAYER_ETHERNET};
    info.fields["eth_src"] = {6, 6, LAYER_ETHERNET};
    info.fields["eth_type"] = {12, 2, LAYER_ETHERNET};

    int nextOffset = 14;

    // 根据以太网类型解析上层协议
    switch (ethType) {
    case 0x0800: // IPv4
        nextOffset = parseIpV4(data, 14, info, parent);
        break;
    case 0x0806: // ARP
        nextOffset = parseArp(data, 14, info, parent);
        break;
    case 0x86DD: // IPv6
        nextOffset = parseIpV6(data, 14, info, parent);
        break;
    default:
        info.protocol = "未知";
        info.info = QString("以太网类型: %1").arg(info.ethType);
        break;
    }

    // 如果没有设置信息字符串，设置默认值
    if (info.info.isEmpty()) {
        if (!info.appProtocol.isEmpty()) {
            // 对于已识别的应用层协议但没有详细信息的情况
            info.info = info.appProtocol;
        } else if (!info.srcPort.isEmpty() && !info.dstPort.isEmpty()) {
            // 对于TCP/UDP但未识别应用层的情况
            info.info = QString("%1 → %2").arg(info.srcPort).arg(info.dstPort);
        } else if (!info.srcIp.isEmpty() && !info.dstIp.isEmpty()) {
            // 对于有IP但没有传输层的情况
            info.info = QString("%1 → %2").arg(info.srcIp).arg(info.dstIp);
        } else {
            // 其他情况
            info.info = info.protocol;
        }
    }

    return nextOffset;
}

// 解析ARP包
int MainWindow::parseArp(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    // ARP包固定长度28字节
    if (data.size() < offset + 28) return -1;

    const uchar *arp = (const uchar*)data.constData() + offset;

    info.protocol = "ARP";

    // 获取操作码
    quint16 op = (arp[6] << 8) | arp[7];

    // 存储ARP字段位置
    info.fields["arp_packet"] = {offset, 28, LAYER_IP};
    info.fields["arp_htype"] = {offset, 2, LAYER_IP};
    info.fields["arp_ptype"] = {offset + 2, 2, LAYER_IP};
    info.fields["arp_hlen"] = {offset + 4, 1, LAYER_IP};
    info.fields["arp_plen"] = {offset + 5, 1, LAYER_IP};
    info.fields["arp_op"] = {offset + 6, 2, LAYER_IP};
    info.fields["arp_sha"] = {offset + 8, 6, LAYER_IP};
    info.fields["arp_spa"] = {offset + 14, 4, LAYER_IP};
    info.fields["arp_tha"] = {offset + 18, 6, LAYER_IP};
    info.fields["arp_tpa"] = {offset + 24, 4, LAYER_IP};

    // 提取源IP和目的IP（用于显示）
    info.srcIp = ipToString(arp + 14);
    info.dstIp = ipToString(arp + 24);

    // 生成信息字符串
    QString senderMac = macToString(arp + 8);
    QString targetMac = macToString(arp + 18);
    if (op == 1) {
        info.info = QString("Who has %1? Tell %2").arg(info.dstIp).arg(info.srcIp);
    } else if (op == 2) {
        info.info = QString("%1 is at %2").arg(info.srcIp).arg(senderMac);
    } else {
        info.info = QString("ARP操作码: %1").arg(op);
    }

    return offset + 28;
}

// 解析IPv4包
int MainWindow::parseIpV4(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    // IPv4头部最少20字节
    if (data.size() < offset + 20) return -1;

    const uchar *ip = (const uchar*)data.constData() + offset;

    // 获取IP头部长度（IHL字段）
    int ipHeaderLen = (ip[0] & 0x0F) * 4;
    if (ipHeaderLen < 20 || data.size() < offset + ipHeaderLen) return -1;

    // 获取总长度
    quint16 totalLen = (ip[2] << 8) | ip[3];
    if (totalLen > data.size() - offset) {
        totalLen = data.size() - offset; // 防止越界
    }

    // 解析源IP和目的IP
    info.srcIp = ipToString(ip + 12);
    info.dstIp = ipToString(ip + 16);

    // 获取协议类型
    quint8 proto = ip[9];

    // 存储IP层字段位置
    info.fields["ip_header"] = {offset, ipHeaderLen, LAYER_IP};
    info.fields["ip_ver_ihl"] = {offset, 1, LAYER_IP};
    info.fields["ip_tos"] = {offset + 1, 1, LAYER_IP};
    info.fields["ip_len"] = {offset + 2, 2, LAYER_IP};
    info.fields["ip_id"] = {offset + 4, 2, LAYER_IP};
    info.fields["ip_flags_frag"] = {offset + 6, 2, LAYER_IP};
    info.fields["ip_ttl"] = {offset + 8, 1, LAYER_IP};
    info.fields["ip_proto"] = {offset + 9, 1, LAYER_IP};
    info.fields["ip_checksum"] = {offset + 10, 2, LAYER_IP};
    info.fields["ip_src"] = {offset + 12, 4, LAYER_IP};
    info.fields["ip_dst"] = {offset + 16, 4, LAYER_IP};

    int transportOffset = offset + ipHeaderLen;
    int transportLen = totalLen - ipHeaderLen;

    // 根据协议类型解析传输层
    switch (proto) {
    case 1: // ICMP
        info.protocol = "ICMP";
        parseIcmp(data, transportOffset, transportLen, info, parent);
        break;
    case 6: // TCP
        info.protocol = "TCP";
        parseTcp(data, transportOffset, transportLen, info, parent);
        break;
    case 17: // UDP
        info.protocol = "UDP";
        parseUdp(data, transportOffset, transportLen, info, parent);
        break;
    default:
        info.protocol = QString("IP-Proto-%1").arg(proto);
        break;
    }

    return offset + totalLen;
}

// 解析IPv6包
int MainWindow::parseIpV6(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    // IPv6固定头部40字节
    if (data.size() < offset + 40) return -1;

    const uchar *ipv6 = (const uchar*)data.constData() + offset;

    info.protocol = "IPv6";
    info.srcIp = ipv6ToString(ipv6 + 8);
    info.dstIp = ipv6ToString(ipv6 + 24);

    // 存储IPv6头部字段位置
    info.fields["ipv6_header"] = {offset, 40, LAYER_IP};
    info.fields["ipv6_ver_class_flow"] = {offset, 4, LAYER_IP};
    info.fields["ipv6_payload_len"] = {offset + 4, 2, LAYER_IP};
    info.fields["ipv6_next_header"] = {offset + 6, 1, LAYER_IP};
    info.fields["ipv6_hop_limit"] = {offset + 7, 1, LAYER_IP};
    info.fields["ipv6_src"] = {offset + 8, 16, LAYER_IP};
    info.fields["ipv6_dst"] = {offset + 24, 16, LAYER_IP};

    // 获取下一个头部类型
    quint8 nextHeader = ipv6[6];
    quint16 payloadLen = (ipv6[4] << 8) | ipv6[5];

    int transportOffset = offset + 40;

    // 简化处理：只处理常见的传输层协议
    switch (nextHeader) {
    case 6: // TCP
        info.protocol = "TCP";
        parseTcp(data, transportOffset, payloadLen, info, parent);
        break;
    case 17: // UDP
        info.protocol = "UDP";
        parseUdp(data, transportOffset, payloadLen, info, parent);
        break;
    case 58: // ICMPv6
        info.protocol = "ICMPv6";
        info.info = "ICMPv6";
        break;
    default:
        info.protocol = QString("IPv6-Next-%1").arg(nextHeader);
        info.info = QString("IPv6 Next Header: %1").arg(nextHeader);
        break;
    }

    return offset + 40 + payloadLen;
}

// 解析ICMP包
int MainWindow::parseIcmp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent) {
    // ICMP头部最少8字节
    if (len < 8 || data.size() < offset + 8) return -1;

    const uchar *icmp = (const uchar*)data.constData() + offset;

    quint8 type = icmp[0];
    quint8 code = icmp[1];

    // 更新协议显示为简单的"ICMP"
    info.protocol = "ICMP";

    // 生成详细的信息字符串
    switch (type) {
    case 0:
        info.info = QString("Echo (ping) reply id=0x%1, seq=%2")
                        .arg((icmp[4] << 8) | icmp[5], 4, 16, QChar('0'))
                        .arg((icmp[6] << 8) | icmp[7]);
        break;
    case 3:
    {
        QString destUnreach;
        switch (code) {
        case 0: destUnreach = "Network unreachable"; break;
        case 1: destUnreach = "Host unreachable"; break;
        case 2: destUnreach = "Protocol unreachable"; break;
        case 3: destUnreach = "Port unreachable"; break;
        case 4: destUnreach = "Fragmentation needed"; break;
        default: destUnreach = QString("Code %1").arg(code);
        }
        info.info = QString("Destination unreachable (%1)").arg(destUnreach);
    }
    break;
    case 8:
        info.info = QString("Echo (ping) request id=0x%1, seq=%2")
                        .arg((icmp[4] << 8) | icmp[5], 4, 16, QChar('0'))
                        .arg((icmp[6] << 8) | icmp[7]);
        break;
    case 11:
        if (code == 0) {
            info.info = "Time-to-live exceeded in transit";
        } else {
            info.info = "Fragment reassembly time exceeded";
        }
        break;
    default:
        info.info = QString("Type %1, Code %2").arg(type).arg(code);
        break;
    }

    // 存储ICMP字段位置
    info.fields["icmp_header"] = {offset, 8, LAYER_TRANSPORT};
    info.fields["icmp_type"] = {offset, 1, LAYER_TRANSPORT};
    info.fields["icmp_code"] = {offset + 1, 1, LAYER_TRANSPORT};
    info.fields["icmp_checksum"] = {offset + 2, 2, LAYER_TRANSPORT};
    info.fields["icmp_data"] = {offset + 4, 4, LAYER_TRANSPORT};

    return offset + len;
}

// 解析TCP包
int MainWindow::parseTcp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent) {
    // TCP头部最少20字节
    if (len < 20 || data.size() < offset + 20) return -1;

    const uchar *tcp = (const uchar*)data.constData() + offset;

    // 获取端口号
    quint16 srcPort = (tcp[0] << 8) | tcp[1];
    quint16 dstPort = (tcp[2] << 8) | tcp[3];
    info.srcPort = QString::number(srcPort);
    info.dstPort = QString::number(dstPort);

    // 获取TCP头部长度
    int tcpHeaderLen = (tcp[12] >> 4) * 4;
    if (tcpHeaderLen < 20 || tcpHeaderLen > len || data.size() < offset + tcpHeaderLen) {
        return -1;
    }

    // 获取序列号和确认号
    quint32 seq = (tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
    quint32 ack = (tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8) | tcp[11];

    // 获取标志位
    quint8 flags = tcp[13];
    QStringList flagList;
    if (flags & 0x01) flagList.append("FIN");
    if (flags & 0x02) flagList.append("SYN");
    if (flags & 0x04) flagList.append("RST");
    if (flags & 0x08) flagList.append("PSH");
    if (flags & 0x10) flagList.append("ACK");
    if (flags & 0x20) flagList.append("URG");

    // 生成信息字符串
    QString flagStr = flagList.isEmpty() ? "" : QString(" [%1]").arg(flagList.join(", "));
    int dataLen = len - tcpHeaderLen;

    if (dataLen > 0) {
        info.info = QString("%1 → %2%3 Seq=%4 Ack=%5 Len=%6")
                        .arg(srcPort).arg(dstPort).arg(flagStr).arg(seq).arg(ack).arg(dataLen);
    } else {
        info.info = QString("%1 → %2%3 Seq=%4 Ack=%5")
                        .arg(srcPort).arg(dstPort).arg(flagStr).arg(seq).arg(ack);
    }

    // 存储TCP字段位置
    info.fields["tcp_header"] = {offset, tcpHeaderLen, LAYER_TRANSPORT};
    info.fields["tcp_srcport"] = {offset, 2, LAYER_TRANSPORT};
    info.fields["tcp_dstport"] = {offset + 2, 2, LAYER_TRANSPORT};
    info.fields["tcp_seq"] = {offset + 4, 4, LAYER_TRANSPORT};
    info.fields["tcp_ack"] = {offset + 8, 4, LAYER_TRANSPORT};
    info.fields["tcp_hdr_flags"] = {offset + 12, 2, LAYER_TRANSPORT};
    info.fields["tcp_window"] = {offset + 14, 2, LAYER_TRANSPORT};
    info.fields["tcp_checksum"] = {offset + 16, 2, LAYER_TRANSPORT};
    info.fields["tcp_urgent"] = {offset + 18, 2, LAYER_TRANSPORT};

    // 解析应用层协议
    int appOffset = offset + tcpHeaderLen;
    int appLen = len - tcpHeaderLen;
    if (appLen > 0 && data.size() > appOffset) {
        parseApplicationLayer(data, appOffset, appLen, srcPort, dstPort, info, parent);
    }

    return offset + len;
}

// 解析UDP包
int MainWindow::parseUdp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent) {
    // UDP头部固定8字节
    if (len < 8 || data.size() < offset + 8) return -1;

    const uchar *udp = (const uchar*)data.constData() + offset;

    // 获取端口号
    quint16 srcPort = (udp[0] << 8) | udp[1];
    quint16 dstPort = (udp[2] << 8) | udp[3];
    info.srcPort = QString::number(srcPort);
    info.dstPort = QString::number(dstPort);

    // 获取UDP长度
    quint16 udpLen = (udp[4] << 8) | udp[5];
    int dataLen = udpLen - 8;

    // 生成信息字符串
    info.info = QString("Source port: %1  Destination port: %2  Len=%3")
                    .arg(srcPort).arg(dstPort).arg(dataLen);

    // 存储UDP字段位置
    info.fields["udp_header"] = {offset, 8, LAYER_TRANSPORT};
    info.fields["udp_srcport"] = {offset, 2, LAYER_TRANSPORT};
    info.fields["udp_dstport"] = {offset + 2, 2, LAYER_TRANSPORT};
    info.fields["udp_len"] = {offset + 4, 2, LAYER_TRANSPORT};
    info.fields["udp_checksum"] = {offset + 6, 2, LAYER_TRANSPORT};

    // 解析应用层协议
    int appOffset = offset + 8;
    int appLen = udpLen - 8;
    if (appLen > 0 && data.size() > appOffset) {
        parseApplicationLayer(data, appOffset, appLen, srcPort, dstPort, info, parent);
    }

    return offset + udpLen;
}

// 解析应用层协议
void MainWindow::parseApplicationLayer(const QByteArray &data, int offset, int len, quint16 srcPort, quint16 dstPort, PacketInfo &info, ProtocolTreeItem *parent) {
    if (len <= 0 || data.size() <= offset) return;

    // HTTP (端口 80, 8080)
    if (srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080) {
        // 检查HTTP方法或响应
        static const QList<QByteArray> httpMethods = {"GET ", "POST", "HTTP", "HEAD", "PUT ", "DELE", "PATC", "TRAC", "CONN", "OPTI"};
        if (len >= 4) {
            QByteArray header = data.mid(offset, qMin(10, len));
            for (const auto &method : httpMethods) {
                if (header.startsWith(method)) {
                    info.appProtocol = "HTTP";
                    info.fields["app_data"] = {offset, len, LAYER_APPLICATION};

                    // 生成HTTP信息
                    QString firstLine = QString::fromUtf8(data.mid(offset, qMin(100, len))).split("\r\n").first();
                    info.info = firstLine;
                    return;
                }
            }
        }
    }

    // HTTPS/TLS (端口 443)
    if (srcPort == 443 || dstPort == 443) {
        if (len >= 6) {
            const uchar *tls = (const uchar*)data.constData() + offset;
            // TLS记录层：ContentType=22(Handshake), Version=0x0301/0x0302/0x0303
            if (tls[0] == 0x16 && tls[1] == 0x03 && (tls[2] >= 0x01 && tls[2] <= 0x04)) {
                info.appProtocol = "HTTPS/TLS";
                info.fields["app_data"] = {offset, len, LAYER_APPLICATION};

                QString contentType;
                switch (tls[0]) {
                case 0x14: contentType = "Change Cipher Spec"; break;
                case 0x15: contentType = "Alert"; break;
                case 0x16: contentType = "Handshake"; break;
                case 0x17: contentType = "Application Data"; break;
                default: contentType = QString("Type %1").arg(tls[0]);
                }
                info.info = QString("TLS %1, Length=%2").arg(contentType).arg((tls[3] << 8) | tls[4]);
                return;
            }
        }
    }

    // DNS (端口 53)
    if (srcPort == 53 || dstPort == 53) {
        info.appProtocol = "DNS";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};

        if (len >= 12) {
            const uchar *dns = (const uchar*)data.constData() + offset;
            quint16 flags = (dns[2] << 8) | dns[3];
            bool qr = (flags >> 15) & 1;
            quint16 questions = (dns[4] << 8) | dns[5];
            quint16 answers = (dns[6] << 8) | dns[7];

            if (qr == 0) {
                // 查询
                info.info = QString("Standard query");
                if (questions > 0 && len > 12) {
                    // 尝试解析域名
                    int nameOffset = offset + 12;
                    QString domainName = parseDnsName(data, nameOffset, offset);
                    if (!domainName.isEmpty()) {
                        info.info += QString(" %1").arg(domainName);
                    }
                }
            } else {
                // 响应
                info.info = QString("Standard query response");
                if (answers > 0) {
                    info.info += QString(", %1 answer(s)").arg(answers);
                }
            }
        }
        return;
    }

    // DHCP (端口 67, 68)
    if ((srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67)) {
        info.appProtocol = "DHCP";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};

        if (len >= 240) {
            const uchar *dhcp = (const uchar*)data.constData() + offset;
            quint8 op = dhcp[0];

            // 查找DHCP消息类型选项
            if (len >= 244) {
                int optOffset = offset + 240;
                if (data.size() >= optOffset + 4) {
                    const uchar *magic = (const uchar*)data.constData() + optOffset;
                    if (magic[0] == 0x63 && magic[1] == 0x82 && magic[2] == 0x53 && magic[3] == 0x63) {
                        // 解析选项找消息类型
                        int currentOffset = optOffset + 4;
                        while (currentOffset < offset + len && currentOffset < data.size()) {
                            uchar optType = data[currentOffset];
                            if (optType == 255) break; // End option
                            if (optType == 0) { currentOffset++; continue; } // Pad option

                            if (currentOffset + 1 >= data.size()) break;
                            uchar optLen = data[currentOffset + 1];

                            if (optType == 53 && optLen == 1 && currentOffset + 2 < data.size()) {
                                uchar msgType = data[currentOffset + 2];
                                switch (msgType) {
                                case 1: info.info = "DHCP Discover"; break;
                                case 2: info.info = "DHCP Offer"; break;
                                case 3: info.info = "DHCP Request"; break;
                                case 4: info.info = "DHCP Decline"; break;
                                case 5: info.info = "DHCP ACK"; break;
                                case 6: info.info = "DHCP NAK"; break;
                                case 7: info.info = "DHCP Release"; break;
                                case 8: info.info = "DHCP Inform"; break;
                                default: info.info = QString("DHCP Message Type %1").arg(msgType);
                                }
                                return;
                            }
                            currentOffset += 2 + optLen;
                        }
                    }
                }
            }

            // 如果没找到消息类型，使用操作码
            info.info = (op == 1) ? "Boot Request" : "Boot Reply";
        }
        return;
    }

    // FTP (端口 21控制, 20数据)
    if (srcPort == 21 || dstPort == 21) {
        info.appProtocol = "FTP";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};

        // 尝试解析FTP命令/响应
        QString ftpData = QString::fromUtf8(data.mid(offset, qMin(100, len))).trimmed();
        info.info = ftpData.left(50);
        if (ftpData.length() > 50) info.info += "...";
        return;
    }
    if (srcPort == 20 || dstPort == 20) {
        info.appProtocol = "FTP-DATA";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};
        info.info = QString("FTP Data: %1 bytes").arg(len);
        return;
    }

    // SSH (端口 22)
    if (srcPort == 22 || dstPort == 22) {
        info.appProtocol = "SSH";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};
        info.info = QString("Encrypted SSH packet, len=%1").arg(len);
        return;
    }

    // Telnet (端口 23)
    if (srcPort == 23 || dstPort == 23) {
        info.appProtocol = "Telnet";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};
        info.info = "Telnet Data";
        return;
    }

    // SMTP (端口 25)
    if (srcPort == 25 || dstPort == 25) {
        info.appProtocol = "SMTP";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};

        QString smtpData = QString::fromUtf8(data.mid(offset, qMin(100, len))).trimmed();
        info.info = smtpData.left(50);
        if (smtpData.length() > 50) info.info += "...";
        return;
    }

    // POP3 (端口 110)
    if (srcPort == 110 || dstPort == 110) {
        info.appProtocol = "POP3";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};
        info.info = "POP3 Data";
        return;
    }

    // IMAP (端口 143)
    if (srcPort == 143 || dstPort == 143) {
        info.appProtocol = "IMAP";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};
        info.info = "IMAP Data";
        return;
    }

    // SNMP (端口 161, 162)
    if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) {
        info.appProtocol = "SNMP";
        info.fields["app_data"] = {offset, len, LAYER_APPLICATION};
        info.info = (dstPort == 162) ? "SNMP Trap" : "SNMP";
        return;
    }

    // 未识别的应用层协议
    info.appProtocol = "";
}

// 解析HTTP协议详细信息
void MainWindow::parseHTTP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
    if (len <= 0 || data.size() <= offset) return;

    // 限制解析长度，避免过大的HTTP请求
    int parseLen = qMin(len, 2000);
    QString httpData = QString::fromUtf8(data.mid(offset, parseLen));
    QStringList lines = httpData.split("\r\n");

    int currentOffset = offset;
    bool headerEnd = false;

    for (const QString &line : lines) {
        if (line.isEmpty()) {
            // 空行表示HTTP头部结束
            headerEnd = true;
            currentOffset += 2;
            break;
        }

        // 添加HTTP头部行
        ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << line);
        item->setFieldInfo(currentOffset, line.toUtf8().length(), LAYER_APPLICATION);
        parent->addChild(item);

        currentOffset += line.toUtf8().length() + 2; // +2 for \r\n
    }

    // 如果存在HTTP body
    if (headerEnd && data.size() > currentOffset) {
        int bodyLen = data.size() - currentOffset;
        ProtocolTreeItem *body = new ProtocolTreeItem(QStringList() << QString("HTTP Body (%1 bytes)").arg(bodyLen));
        body->setFieldInfo(currentOffset, bodyLen, LAYER_APPLICATION);
        parent->addChild(body);

        // 显示body的前100字节预览
        if (bodyLen > 0) {
            QString bodyPreview = QString::fromUtf8(data.mid(currentOffset, qMin(100, bodyLen)));
            bodyPreview.replace("\r", "\\r").replace("\n", "\\n");
            if (bodyLen > 100) {
                bodyPreview += "...";
            }
            ProtocolTreeItem *preview = new ProtocolTreeItem(QStringList() << QString("预览: %1").arg(bodyPreview));
            preview->setFieldInfo(currentOffset, qMin(100, bodyLen), LAYER_APPLICATION);
            body->addChild(preview);
        }
    }
}

// 解析DNS协议详细信息
void MainWindow::parseDNS(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
    if (len < 12 || data.size() < offset + 12) return;

    const uchar *dns = (const uchar*)data.constData() + offset;

    // DNS头部
    quint16 transId = (dns[0] << 8) | dns[1];
    quint16 flags = (dns[2] << 8) | dns[3];
    quint16 questions = (dns[4] << 8) | dns[5];
    quint16 answers = (dns[6] << 8) | dns[7];
    quint16 authority = (dns[8] << 8) | dns[9];
    quint16 additional = (dns[10] << 8) | dns[11];

    // 事务ID
    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("事务ID: 0x%1").arg(transId, 4, 16, QChar('0')));
    item->setFieldInfo(offset, 2, LAYER_APPLICATION);
    parent->addChild(item);

    // 标志
    ProtocolTreeItem *flagsItem = new ProtocolTreeItem(QStringList() << QString("标志: 0x%1").arg(flags, 4, 16, QChar('0')));
    flagsItem->setFieldInfo(offset + 2, 2, LAYER_APPLICATION);
    parent->addChild(flagsItem);

    // 解析标志位
    bool qr = (flags >> 15) & 1;        // 查询/响应标志
    int opcode = (flags >> 11) & 0xF;   // 操作码
    bool aa = (flags >> 10) & 1;        // 授权回答
    bool tc = (flags >> 9) & 1;         // 截断标志
    bool rd = (flags >> 8) & 1;         // 期望递归
    bool ra = (flags >> 7) & 1;         // 递归可用
    int rcode = flags & 0xF;            // 响应码

    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("查询/响应: %1").arg(qr ? "响应" : "查询")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("操作码: %1").arg(opcode)));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("授权回答: %1").arg(aa ? "是" : "否")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("截断: %1").arg(tc ? "是" : "否")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("期望递归: %1").arg(rd ? "是" : "否")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("递归可用: %1").arg(ra ? "是" : "否")));

    QString rcodeStr;
    switch (rcode) {
    case 0: rcodeStr = "无错误"; break;
    case 1: rcodeStr = "格式错误"; break;
    case 2: rcodeStr = "服务器失败"; break;
    case 3: rcodeStr = "名称错误"; break;
    case 4: rcodeStr = "未实现"; break;
    case 5: rcodeStr = "拒绝"; break;
    default: rcodeStr = QString::number(rcode);
    }
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("响应码: %1 - %2").arg(rcode).arg(rcodeStr)));

    // 计数字段
    item = new ProtocolTreeItem(QStringList() << QString("问题数: %1").arg(questions));
    item->setFieldInfo(offset + 4, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("回答数: %1").arg(answers));
    item->setFieldInfo(offset + 6, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("授权数: %1").arg(authority));
    item->setFieldInfo(offset + 8, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("附加数: %1").arg(additional));
    item->setFieldInfo(offset + 10, 2, LAYER_APPLICATION);
    parent->addChild(item);

    // 解析查询部分
    int currentOffset = offset + 12;
    if (questions > 0 && data.size() > currentOffset) {
        ProtocolTreeItem *queriesItem = new ProtocolTreeItem(QStringList() << "查询");
        parent->addChild(queriesItem);

        for (int i = 0; i < questions && currentOffset < data.size(); i++) {
            // 解析域名
            QString domainName = parseDnsName(data, currentOffset, offset);
            if (domainName.isEmpty()) break;

            if (data.size() >= currentOffset + 4) {
                const uchar *query = (const uchar*)data.constData() + currentOffset;
                quint16 qtype = (query[0] << 8) | query[1];
                quint16 qclass = (query[2] << 8) | query[3];

                QString typeStr;
                switch (qtype) {
                case 1: typeStr = "A"; break;
                case 2: typeStr = "NS"; break;
                case 5: typeStr = "CNAME"; break;
                case 6: typeStr = "SOA"; break;
                case 12: typeStr = "PTR"; break;
                case 15: typeStr = "MX"; break;
                case 28: typeStr = "AAAA"; break;
                case 33: typeStr = "SRV"; break;
                default: typeStr = QString::number(qtype);
                }

                ProtocolTreeItem *queryItem = new ProtocolTreeItem(QStringList() <<
                                                                   QString("查询 %1: %2, 类型=%3, 类=%4").arg(i+1).arg(domainName).arg(typeStr).arg(qclass));
                queriesItem->addChild(queryItem);

                currentOffset += 4;
            }
        }
    }
}

// 解析DNS域名
QString MainWindow::parseDnsName(const QByteArray &data, int &offset, int baseOffset) {
    QString name;
    int jumped = 0;
    int savedOffset = -1;

    while (offset < data.size()) {
        uchar len = data[offset];

        if (len == 0) {
            // 域名结束
            offset++;
            break;
        } else if ((len & 0xC0) == 0xC0) {
            // 压缩指针
            if (offset + 1 >= data.size()) break;

            if (savedOffset < 0) {
                savedOffset = offset + 2;
            }

            int pointer = ((len & 0x3F) << 8) | (uchar)data[offset + 1];
            offset = baseOffset + pointer;

            // 防止无限循环
            if (++jumped > 5) break;
        } else {
            // 普通标签
            if (offset + len + 1 > data.size()) break;

            if (!name.isEmpty()) name += ".";
            name += QString::fromUtf8(data.mid(offset + 1, len));
            offset += len + 1;
        }
    }

    if (savedOffset >= 0) {
        offset = savedOffset;
    }

    return name;
}

// 解析DHCP协议详细信息
void MainWindow::parseDHCP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
    if (len < 240 || data.size() < offset + 240) return;

    const uchar *dhcp = (const uchar*)data.constData() + offset;

    // DHCP消息类型
    quint8 op = dhcp[0];
    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("消息类型: %1 (%2)")
                                                                       .arg(op).arg(op == 1 ? "Boot Request" : "Boot Reply"));
    item->setFieldInfo(offset, 1, LAYER_APPLICATION);
    parent->addChild(item);

    // 硬件类型
    quint8 htype = dhcp[1];
    item = new ProtocolTreeItem(QStringList() << QString("硬件类型: %1 (Ethernet)").arg(htype));
    item->setFieldInfo(offset + 1, 1, LAYER_APPLICATION);
    parent->addChild(item);

    // 硬件地址长度
    quint8 hlen = dhcp[2];
    item = new ProtocolTreeItem(QStringList() << QString("硬件地址长度: %1").arg(hlen));
    item->setFieldInfo(offset + 2, 1, LAYER_APPLICATION);
    parent->addChild(item);

    // 跳数
    quint8 hops = dhcp[3];
    item = new ProtocolTreeItem(QStringList() << QString("跳数: %1").arg(hops));
    item->setFieldInfo(offset + 3, 1, LAYER_APPLICATION);
    parent->addChild(item);

    // 事务ID
    quint32 xid = (dhcp[4] << 24) | (dhcp[5] << 16) | (dhcp[6] << 8) | dhcp[7];
    item = new ProtocolTreeItem(QStringList() << QString("事务ID: 0x%1").arg(xid, 8, 16, QChar('0')));
    item->setFieldInfo(offset + 4, 4, LAYER_APPLICATION);
    parent->addChild(item);

    // 时间
    quint16 secs = (dhcp[8] << 8) | dhcp[9];
    item = new ProtocolTreeItem(QStringList() << QString("已过秒数: %1").arg(secs));
    item->setFieldInfo(offset + 8, 2, LAYER_APPLICATION);
    parent->addChild(item);

    // 标志
    quint16 flags = (dhcp[10] << 8) | dhcp[11];
    item = new ProtocolTreeItem(QStringList() << QString("标志: 0x%1").arg(flags, 4, 16, QChar('0')));
    item->setFieldInfo(offset + 10, 2, LAYER_APPLICATION);
    parent->addChild(item);

    if (flags & 0x8000) {
        item->addChild(new QTreeWidgetItem(QStringList() << "广播标志: 设置"));
    }

    // IP地址
    item = new ProtocolTreeItem(QStringList() << QString("客户端IP: %1").arg(ipToString(dhcp + 12)));
    item->setFieldInfo(offset + 12, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("您的IP: %1").arg(ipToString(dhcp + 16)));
    item->setFieldInfo(offset + 16, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("服务器IP: %1").arg(ipToString(dhcp + 20)));
    item->setFieldInfo(offset + 20, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("网关IP: %1").arg(ipToString(dhcp + 24)));
    item->setFieldInfo(offset + 24, 4, LAYER_APPLICATION);
    parent->addChild(item);

    // 客户端硬件地址
    item = new ProtocolTreeItem(QStringList() << QString("客户端MAC: %1").arg(macToString(dhcp + 28)));
    item->setFieldInfo(offset + 28, 16, LAYER_APPLICATION);
    parent->addChild(item);

    // 检查魔术字段（DHCP选项）
    if (len >= 240 && data.size() >= offset + 240) {
        int optOffset = offset + 236;
        if (data.size() >= optOffset + 4) {
            const uchar *magic = (const uchar*)data.constData() + optOffset;
            if (magic[0] == 0x63 && magic[1] == 0x82 && magic[2] == 0x53 && magic[3] == 0x63) {
                // 解析DHCP选项
                parseDhcpOptions(data, optOffset + 4, len - 240, parent);
            }
        }
    }
}

// 解析DHCP选项
void MainWindow::parseDhcpOptions(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
    ProtocolTreeItem *optionsItem = new ProtocolTreeItem(QStringList() << "DHCP选项");
    parent->addChild(optionsItem);

    int currentOffset = offset;
    int endOffset = offset + len;

    while (currentOffset < endOffset && currentOffset < data.size()) {
        uchar optType = data[currentOffset];

        if (optType == 0) {
            // Pad选项
            currentOffset++;
            continue;
        } else if (optType == 255) {
            // End选项
            ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << "选项255: 结束");
            optionsItem->addChild(item);
            break;
        }

        if (currentOffset + 1 >= data.size()) break;
        uchar optLen = data[currentOffset + 1];

        if (currentOffset + 2 + optLen > data.size()) break;

        QString optName;
        QString optValue;

        switch (optType) {
        case 1: // 子网掩码
            if (optLen == 4) {
                optName = "子网掩码";
                optValue = ipToString((const uchar*)data.constData() + currentOffset + 2);
            }
            break;
        case 3: // 路由器
            optName = "路由器";
            if (optLen >= 4) {
                optValue = ipToString((const uchar*)data.constData() + currentOffset + 2);
            }
            break;
        case 6: // DNS服务器
            optName = "DNS服务器";
            if (optLen >= 4) {
                optValue = ipToString((const uchar*)data.constData() + currentOffset + 2);
                if (optLen >= 8) {
                    optValue += ", " + ipToString((const uchar*)data.constData() + currentOffset + 6);
                }
            }
            break;
        case 12: // 主机名
            optName = "主机名";
            optValue = QString::fromUtf8(data.mid(currentOffset + 2, optLen));
            break;
        case 15: // 域名
            optName = "域名";
            optValue = QString::fromUtf8(data.mid(currentOffset + 2, optLen));
            break;
        case 50: // 请求的IP地址
            if (optLen == 4) {
                optName = "请求的IP地址";
                optValue = ipToString((const uchar*)data.constData() + currentOffset + 2);
            }
            break;
        case 51: // 租约时间
            if (optLen == 4) {
                optName = "租约时间";
                const uchar *lease = (const uchar*)data.constData() + currentOffset + 2;
                quint32 time = (lease[0] << 24) | (lease[1] << 16) | (lease[2] << 8) | lease[3];
                optValue = QString("%1 秒").arg(time);
            }
            break;
        case 53: // DHCP消息类型
            if (optLen == 1) {
                optName = "DHCP消息类型";
                uchar msgType = data[currentOffset + 2];
                switch (msgType) {
                case 1: optValue = "DHCP Discover"; break;
                case 2: optValue = "DHCP Offer"; break;
                case 3: optValue = "DHCP Request"; break;
                case 4: optValue = "DHCP Decline"; break;
                case 5: optValue = "DHCP ACK"; break;
                case 6: optValue = "DHCP NAK"; break;
                case 7: optValue = "DHCP Release"; break;
                case 8: optValue = "DHCP Inform"; break;
                default: optValue = QString::number(msgType);
                }
            }
            break;
        case 54: // DHCP服务器标识
            if (optLen == 4) {
                optName = "DHCP服务器";
                optValue = ipToString((const uchar*)data.constData() + currentOffset + 2);
            }
            break;
        case 55: // 参数请求列表
            optName = "参数请求列表";
            optValue = QString("%1个参数").arg(optLen);
            break;
        default:
            optName = QString("选项%1").arg(optType);
            optValue = QString("长度=%1").arg(optLen);
        }

        ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("%1: %2").arg(optName).arg(optValue));
        item->setFieldInfo(currentOffset, 2 + optLen, LAYER_APPLICATION);
        optionsItem->addChild(item);

        currentOffset += 2 + optLen;
    }
}

void MainWindow::onPacketTableClicked(int row, int /*column*/) {
    // 使用映射表找到实际的数据包索引
    if (!rowToPacketIndex.contains(row)) return;

    int packetIndex = rowToPacketIndex[row];
    if (packetIndex < 0 || packetIndex >= packetList.size()) return;

    currentPacketIndex = packetIndex;  // 保存当前选中的数据包索引
    const PacketInfo &info = packetList[packetIndex];
    updateProtocolTree(info);
    updateRawDataView(info.rawData, -1, 0); // 显示原始数据，不高亮
}

void MainWindow::onProtocolTreeItemClicked(QTreeWidgetItem *item, int /*column*/) {
    if (currentPacketIndex < 0 || currentPacketIndex >= packetList.size()) return;

    ProtocolTreeItem *pItem = dynamic_cast<ProtocolTreeItem*>(item);
    if (pItem && pItem->getFieldOffset() >= 0) {
        const PacketInfo &info = packetList[currentPacketIndex];  // 使用当前选中的数据包
        updateRawDataView(info.rawData, pItem->getFieldOffset(),
                          pItem->getFieldLength());
    }
}

void MainWindow::updateProtocolTree(const PacketInfo &info) {
    ui->protocolTree->clear();

    // 以太网层
    ProtocolTreeItem *eth = new ProtocolTreeItem(QStringList() << "以太网 II");
    eth->setFieldInfo(0, 14, LAYER_ETHERNET);

    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << ("目的MAC: " + info.dstMac));
    item->setFieldInfo(0, 6, LAYER_ETHERNET);
    eth->addChild(item);

    item = new ProtocolTreeItem(QStringList() << ("源MAC: " + info.srcMac));
    item->setFieldInfo(6, 6, LAYER_ETHERNET);
    eth->addChild(item);

    item = new ProtocolTreeItem(QStringList() << ("类型: " + info.ethType));
    item->setFieldInfo(12, 2, LAYER_ETHERNET);
    eth->addChild(item);

    ui->protocolTree->addTopLevelItem(eth);

    // IP层
    if (!info.srcIp.isEmpty() && info.fields.contains("ip_header")) {
        const uchar *ipHeader = (const uchar*)info.rawData.constData() + info.fields["ip_header"].offset;

        ProtocolTreeItem *ip = new ProtocolTreeItem(QStringList() << "网际协议版本 4 (IPv4)");
        ip->setFieldInfo(info.fields["ip_header"].offset, info.fields["ip_header"].length, LAYER_IP);

        // IP版本和头部长度
        quint8 ver_ihl = ipHeader[0];
        item = new ProtocolTreeItem(QStringList() << QString("版本: %1").arg(ver_ihl >> 4));
        item->setFieldInfo(info.fields["ip_ver_ihl"].offset, 1, LAYER_IP);
        ip->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("头部长度: %1 字节").arg((ver_ihl & 0x0F) * 4));
        item->setFieldInfo(info.fields["ip_ver_ihl"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 服务类型
        quint8 tos = ipHeader[1];
        item = new ProtocolTreeItem(QStringList() << QString("服务类型: 0x%1").arg(tos, 2, 16, QChar('0')));
        item->setFieldInfo(info.fields["ip_tos"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 总长度
        quint16 totalLen = (ipHeader[2] << 8) | ipHeader[3];
        item = new ProtocolTreeItem(QStringList() << QString("总长度: %1 字节").arg(totalLen));
        item->setFieldInfo(info.fields["ip_len"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // 标识
        quint16 id = (ipHeader[4] << 8) | ipHeader[5];
        item = new ProtocolTreeItem(QStringList() << QString("标识: 0x%1 (%2)").arg(id, 4, 16, QChar('0')).arg(id));
        item->setFieldInfo(info.fields["ip_id"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // 标志和片偏移
        quint16 flags_frag = (ipHeader[6] << 8) | ipHeader[7];
        quint8 flags = (flags_frag >> 13) & 0x07;
        quint16 fragOffset = flags_frag & 0x1FFF;

        ProtocolTreeItem *flagsItem = new ProtocolTreeItem(QStringList() << QString("标志: 0x%1").arg(flags, 1, 16));
        flagsItem->setFieldInfo(info.fields["ip_flags_frag"].offset, 2, LAYER_IP);
        ip->addChild(flagsItem);

        flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("保留位: %1").arg((flags >> 2) & 1)));
        flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("不分片: %1").arg((flags >> 1) & 1)));
        flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("更多分片: %1").arg(flags & 1)));

        item = new ProtocolTreeItem(QStringList() << QString("片偏移: %1").arg(fragOffset));
        item->setFieldInfo(info.fields["ip_flags_frag"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // TTL
        item = new ProtocolTreeItem(QStringList() << QString("生存时间: %1").arg(ipHeader[8]));
        item->setFieldInfo(info.fields["ip_ttl"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 协议
        item = new ProtocolTreeItem(QStringList() << QString("协议: %1 (%2)").arg(info.protocol).arg(ipHeader[9]));
        item->setFieldInfo(info.fields["ip_proto"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 校验和
        quint16 checksum = (ipHeader[10] << 8) | ipHeader[11];
        item = new ProtocolTreeItem(QStringList() << QString("头部校验和: 0x%1").arg(checksum, 4, 16, QChar('0')));
        item->setFieldInfo(info.fields["ip_checksum"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // 源IP和目的IP
        item = new ProtocolTreeItem(QStringList() << ("源IP: " + info.srcIp));
        item->setFieldInfo(info.fields["ip_src"].offset, 4, LAYER_IP);
        ip->addChild(item);

        item = new ProtocolTreeItem(QStringList() << ("目的IP: " + info.dstIp));
        item->setFieldInfo(info.fields["ip_dst"].offset, 4, LAYER_IP);
        ip->addChild(item);

        ui->protocolTree->addTopLevelItem(ip);

        // 传输层
        if (info.protocol == "TCP" && info.fields.contains("tcp_header")) {
            const uchar *tcpHeader = (const uchar*)info.rawData.constData() + info.fields["tcp_header"].offset;

            ProtocolTreeItem *tcp = new ProtocolTreeItem(QStringList() << "传输控制协议 (TCP)");
            tcp->setFieldInfo(info.fields["tcp_header"].offset, info.fields["tcp_header"].length, LAYER_TRANSPORT);

            // 源端口和目的端口
            item = new ProtocolTreeItem(QStringList() << ("源端口: " + info.srcPort));
            item->setFieldInfo(info.fields["tcp_srcport"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            item = new ProtocolTreeItem(QStringList() << ("目的端口: " + info.dstPort));
            item->setFieldInfo(info.fields["tcp_dstport"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 序列号
            quint32 seq = (tcpHeader[4] << 24) | (tcpHeader[5] << 16) | (tcpHeader[6] << 8) | tcpHeader[7];
            item = new ProtocolTreeItem(QStringList() << QString("序列号: %1").arg(seq));
            item->setFieldInfo(info.fields["tcp_seq"].offset, 4, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 确认号
            quint32 ack = (tcpHeader[8] << 24) | (tcpHeader[9] << 16) | (tcpHeader[10] << 8) | tcpHeader[11];
            item = new ProtocolTreeItem(QStringList() << QString("确认号: %1").arg(ack));
            item->setFieldInfo(info.fields["tcp_ack"].offset, 4, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 头部长度和标志
            quint8 hdrLen = (tcpHeader[12] >> 4) * 4;
            quint8 flags = tcpHeader[13];

            item = new ProtocolTreeItem(QStringList() << QString("头部长度: %1 字节").arg(hdrLen));
            item->setFieldInfo(info.fields["tcp_hdr_flags"].offset, 1, LAYER_TRANSPORT);
            tcp->addChild(item);

            ProtocolTreeItem *flagsItem = new ProtocolTreeItem(QStringList() << QString("标志: 0x%1").arg(flags, 2, 16, QChar('0')));
            flagsItem->setFieldInfo(info.fields["tcp_hdr_flags"].offset + 1, 1, LAYER_TRANSPORT);
            tcp->addChild(flagsItem);

            flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("FIN: %1").arg(flags & 0x01)));
            flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("SYN: %1").arg((flags >> 1) & 0x01)));
            flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("RST: %1").arg((flags >> 2) & 0x01)));
            flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("PSH: %1").arg((flags >> 3) & 0x01)));
            flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("ACK: %1").arg((flags >> 4) & 0x01)));
            flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("URG: %1").arg((flags >> 5) & 0x01)));

            // 窗口大小
            quint16 window = (tcpHeader[14] << 8) | tcpHeader[15];
            item = new ProtocolTreeItem(QStringList() << QString("窗口大小: %1").arg(window));
            item->setFieldInfo(info.fields["tcp_window"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 校验和
            quint16 checksum = (tcpHeader[16] << 8) | tcpHeader[17];
            item = new ProtocolTreeItem(QStringList() << QString("校验和: 0x%1").arg(checksum, 4, 16, QChar('0')));
            item->setFieldInfo(info.fields["tcp_checksum"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 紧急指针
            quint16 urgent = (tcpHeader[18] << 8) | tcpHeader[19];
            item = new ProtocolTreeItem(QStringList() << QString("紧急指针: %1").arg(urgent));
            item->setFieldInfo(info.fields["tcp_urgent"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            ui->protocolTree->addTopLevelItem(tcp);

        } else if (info.protocol == "UDP" && info.fields.contains("udp_header")) {
            const uchar *udpHeader = (const uchar*)info.rawData.constData() + info.fields["udp_header"].offset;

            ProtocolTreeItem *udp = new ProtocolTreeItem(QStringList() << "用户数据报协议 (UDP)");
            udp->setFieldInfo(info.fields["udp_header"].offset, info.fields["udp_header"].length, LAYER_TRANSPORT);

            item = new ProtocolTreeItem(QStringList() << ("源端口: " + info.srcPort));
            item->setFieldInfo(info.fields["udp_srcport"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            item = new ProtocolTreeItem(QStringList() << ("目的端口: " + info.dstPort));
            item->setFieldInfo(info.fields["udp_dstport"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            quint16 len = (udpHeader[4] << 8) | udpHeader[5];
            item = new ProtocolTreeItem(QStringList() << QString("长度: %1 字节").arg(len));
            item->setFieldInfo(info.fields["udp_len"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            quint16 checksum = (udpHeader[6] << 8) | udpHeader[7];
            item = new ProtocolTreeItem(QStringList() << QString("校验和: 0x%1").arg(checksum, 4, 16, QChar('0')));
            item->setFieldInfo(info.fields["udp_checksum"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            ui->protocolTree->addTopLevelItem(udp);

        } else if (info.protocol.startsWith("ICMP") && info.fields.contains("icmp_header")) {
            const uchar *icmpHeader = (const uchar*)info.rawData.constData() + info.fields["icmp_header"].offset;

            ProtocolTreeItem *icmp = new ProtocolTreeItem(QStringList() << "互联网控制消息协议 (ICMP)");
            icmp->setFieldInfo(info.fields["icmp_header"].offset, info.fields["icmp_header"].length, LAYER_TRANSPORT);

            quint8 type = icmpHeader[0];
            quint8 code = icmpHeader[1];

            QString typeStr;
            switch(type) {
            case 0: typeStr = "回显应答"; break;
            case 3: typeStr = "目的不可达"; break;
            case 8: typeStr = "回显请求"; break;
            case 11: typeStr = "超时"; break;
            default: typeStr = QString::number(type);
            }

            item = new ProtocolTreeItem(QStringList() << QString("类型: %1 (%2)").arg(type).arg(typeStr));
            item->setFieldInfo(info.fields["icmp_type"].offset, 1, LAYER_TRANSPORT);
            icmp->addChild(item);

            item = new ProtocolTreeItem(QStringList() << QString("代码: %1").arg(code));
            item->setFieldInfo(info.fields["icmp_code"].offset, 1, LAYER_TRANSPORT);
            icmp->addChild(item);

            quint16 checksum = (icmpHeader[2] << 8) | icmpHeader[3];
            item = new ProtocolTreeItem(QStringList() << QString("校验和: 0x%1").arg(checksum, 4, 16, QChar('0')));
            item->setFieldInfo(info.fields["icmp_checksum"].offset, 2, LAYER_TRANSPORT);
            icmp->addChild(item);

            ui->protocolTree->addTopLevelItem(icmp);
        }

        // 应用层
        if (!info.appProtocol.isEmpty() && info.fields.contains("app_data")) {
            ProtocolTreeItem *app = new ProtocolTreeItem(QStringList() << info.appProtocol);
            app->setFieldInfo(info.fields["app_data"].offset, info.fields["app_data"].length, LAYER_APPLICATION);

            // 根据不同协议添加详细解析
            if (info.appProtocol == "HTTP") {
                parseHTTP(info.rawData, info.fields["app_data"].offset, info.fields["app_data"].length, app);
            } else if (info.appProtocol == "DNS") {
                parseDNS(info.rawData, info.fields["app_data"].offset, info.fields["app_data"].length, app);
            } else if (info.appProtocol == "DHCP") {
                parseDHCP(info.rawData, info.fields["app_data"].offset, info.fields["app_data"].length, app);
            } else if (info.appProtocol == "HTTPS/TLS") {
                // TLS协议简单显示
                ProtocolTreeItem *tlsInfo = new ProtocolTreeItem(QStringList() << "TLS/SSL加密数据");
                tlsInfo->setFieldInfo(info.fields["app_data"].offset, info.fields["app_data"].length, LAYER_APPLICATION);
                app->addChild(tlsInfo);

                // 尝试解析TLS记录层
                if (info.fields["app_data"].length >= 5) {
                    const uchar *tls = (const uchar*)info.rawData.constData() + info.fields["app_data"].offset;
                    quint8 contentType = tls[0];
                    quint16 version = (tls[1] << 8) | tls[2];
                    quint16 length = (tls[3] << 8) | tls[4];

                    QString contentTypeStr;
                    switch (contentType) {
                    case 20: contentTypeStr = "ChangeCipherSpec"; break;
                    case 21: contentTypeStr = "Alert"; break;
                    case 22: contentTypeStr = "Handshake"; break;
                    case 23: contentTypeStr = "Application Data"; break;
                    default: contentTypeStr = QString::number(contentType);
                    }

                    tlsInfo->addChild(new QTreeWidgetItem(QStringList() << QString("内容类型: %1").arg(contentTypeStr)));
                    tlsInfo->addChild(new QTreeWidgetItem(QStringList() << QString("版本: 0x%1").arg(version, 4, 16, QChar('0'))));
                    tlsInfo->addChild(new QTreeWidgetItem(QStringList() << QString("长度: %1").arg(length)));
                }
            }

            ui->protocolTree->addTopLevelItem(app);
        }
    } else if (info.protocol == "ARP" && info.fields.contains("arp_packet")) {
        const uchar *arpData = (const uchar*)info.rawData.constData() + info.fields["arp_packet"].offset;

        ProtocolTreeItem *arp = new ProtocolTreeItem(QStringList() << "地址解析协议 (ARP)");
        arp->setFieldInfo(info.fields["arp_packet"].offset, info.fields["arp_packet"].length, LAYER_IP);

        quint16 htype = (arpData[0] << 8) | arpData[1];
        item = new ProtocolTreeItem(QStringList() << QString("硬件类型: %1 (Ethernet)").arg(htype));
        item->setFieldInfo(info.fields["arp_htype"].offset, 2, LAYER_IP);
        arp->addChild(item);

        quint16 ptype = (arpData[2] << 8) | arpData[3];
        item = new ProtocolTreeItem(QStringList() << QString("协议类型: 0x%1 (IPv4)").arg(ptype, 4, 16, QChar('0')));
        item->setFieldInfo(info.fields["arp_ptype"].offset, 2, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("硬件地址长度: %1").arg(arpData[4]));
        item->setFieldInfo(info.fields["arp_hlen"].offset, 1, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("协议地址长度: %1").arg(arpData[5]));
        item->setFieldInfo(info.fields["arp_plen"].offset, 1, LAYER_IP);
        arp->addChild(item);

        quint16 op = (arpData[6] << 8) | arpData[7];
        QString opStr = (op == 1) ? "ARP请求" : (op == 2) ? "ARP应答" : "未知";
        item = new ProtocolTreeItem(QStringList() << QString("操作码: %1 (%2)").arg(op).arg(opStr));
        item->setFieldInfo(info.fields["arp_op"].offset, 2, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("发送方MAC: %1").arg(macToString(arpData + 8)));
        item->setFieldInfo(info.fields["arp_sha"].offset, 6, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("发送方IP: %1").arg(ipToString(arpData + 14)));
        item->setFieldInfo(info.fields["arp_spa"].offset, 4, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("目标MAC: %1").arg(macToString(arpData + 18)));
        item->setFieldInfo(info.fields["arp_tha"].offset, 6, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("目标IP: %1").arg(ipToString(arpData + 24)));
        item->setFieldInfo(info.fields["arp_tpa"].offset, 4, LAYER_IP);
        arp->addChild(item);

        ui->protocolTree->addTopLevelItem(arp);
    } else if (info.protocol == "IPv6" && info.fields.contains("ipv6_header")) {
        const uchar *ipv6Header = (const uchar*)info.rawData.constData() + info.fields["ipv6_header"].offset;

        ProtocolTreeItem *ipv6 = new ProtocolTreeItem(QStringList() << "网际协议版本 6 (IPv6)");
        ipv6->setFieldInfo(info.fields["ipv6_header"].offset, info.fields["ipv6_header"].length, LAYER_IP);

        // 版本、流量类别和流标签
        quint32 ver_class_flow = (ipv6Header[0] << 24) | (ipv6Header[1] << 16) | (ipv6Header[2] << 8) | ipv6Header[3];
        quint8 version = (ver_class_flow >> 28) & 0x0F;
        quint8 trafficClass = (ver_class_flow >> 20) & 0xFF;
        quint32 flowLabel = ver_class_flow & 0xFFFFF;

        item = new ProtocolTreeItem(QStringList() << QString("版本: %1").arg(version));
        item->setFieldInfo(info.fields["ipv6_ver_class_flow"].offset, 4, LAYER_IP);
        ipv6->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("流量类别: 0x%1").arg(trafficClass, 2, 16, QChar('0')));
        item->setFieldInfo(info.fields["ipv6_ver_class_flow"].offset, 4, LAYER_IP);
        ipv6->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("流标签: 0x%1").arg(flowLabel, 5, 16, QChar('0')));
        item->setFieldInfo(info.fields["ipv6_ver_class_flow"].offset, 4, LAYER_IP);
        ipv6->addChild(item);

        // 载荷长度
        quint16 payloadLen = (ipv6Header[4] << 8) | ipv6Header[5];
        item = new ProtocolTreeItem(QStringList() << QString("载荷长度: %1 字节").arg(payloadLen));
        item->setFieldInfo(info.fields["ipv6_payload_len"].offset, 2, LAYER_IP);
        ipv6->addChild(item);

        // 下一个头部
        quint8 nextHeader = ipv6Header[6];
        QString nextHeaderStr;
        switch (nextHeader) {
        case 6: nextHeaderStr = "TCP"; break;
        case 17: nextHeaderStr = "UDP"; break;
        case 58: nextHeaderStr = "ICMPv6"; break;
        default: nextHeaderStr = QString::number(nextHeader);
        }
        item = new ProtocolTreeItem(QStringList() << QString("下一个头部: %1 (%2)").arg(nextHeader).arg(nextHeaderStr));
        item->setFieldInfo(info.fields["ipv6_next_header"].offset, 1, LAYER_IP);
        ipv6->addChild(item);

        // 跳数限制
        item = new ProtocolTreeItem(QStringList() << QString("跳数限制: %1").arg(ipv6Header[7]));
        item->setFieldInfo(info.fields["ipv6_hop_limit"].offset, 1, LAYER_IP);
        ipv6->addChild(item);

        // 源地址和目的地址
        item = new ProtocolTreeItem(QStringList() << QString("源地址: %1").arg(info.srcIp));
        item->setFieldInfo(info.fields["ipv6_src"].offset, 16, LAYER_IP);
        ipv6->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("目的地址: %1").arg(info.dstIp));
        item->setFieldInfo(info.fields["ipv6_dst"].offset, 16, LAYER_IP);
        ipv6->addChild(item);

        ui->protocolTree->addTopLevelItem(ipv6);
    }

    ui->protocolTree->expandAll();
}

void MainWindow::updateRawDataView(const QByteArray &data, int highlightStart, int highlightLen) {
    ui->rawDataEdit->clear();

    QTextCursor cursor(ui->rawDataEdit->document());

    // 设置等宽字体
    QTextCharFormat monoFormat;
    QFont monoFont("Consolas", 10);
    monoFont.setStyleHint(QFont::Monospace);
    monoFormat.setFont(monoFont);

    // 不同层的颜色
    QColor layerColors[4] = {
        QColor(255, 200, 200),  // 以太网层 - 浅红
        QColor(200, 255, 200),  // IP层 - 浅绿
        QColor(200, 200, 255),  // 传输层 - 浅蓝
        QColor(255, 255, 200)   // 应用层 - 浅黄
    };

    for (int i = 0; i < data.size(); i += 16) {
        // 地址
        cursor.insertText(QString("%1  ").arg(i, 4, 16, QChar('0')).toUpper(), monoFormat);

        // 十六进制
        for (int j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                QTextCharFormat format = monoFormat;

                // 高亮选中的字节
                if (highlightStart >= 0 && i + j >= highlightStart && i + j < highlightStart + highlightLen) {
                    format.setBackground(QColor(173, 216, 230)); // 浅蓝色高亮
                    format.setFontWeight(QFont::Bold);
                }

                cursor.insertText(QString("%1 ").arg((quint8)data[i + j], 2, 16, QChar('0')).toUpper(), format);

                if (j == 7) cursor.insertText(" ", monoFormat); // 中间间隔
            } else {
                cursor.insertText("   ", monoFormat);
                if (j == 7) cursor.insertText(" ", monoFormat);
            }
        }

        cursor.insertText("  ", monoFormat);

        // ASCII
        for (int j = 0; j < 16 && i + j < data.size(); ++j) {
            QTextCharFormat format = monoFormat;

            // 高亮选中的字符
            if (highlightStart >= 0 && i + j >= highlightStart && i + j < highlightStart + highlightLen) {
                format.setBackground(QColor(173, 216, 230)); // 浅蓝色高亮
                format.setFontWeight(QFont::Bold);
            }

            char c = data[i + j];
            cursor.insertText(QString(1, (c >= 32 && c <= 126) ? c : '.'), format);
        }

        cursor.insertText("\n", monoFormat);
    }
}

bool MainWindow::filterPacket(const PacketInfo &info) {
    // MAC过滤
    QString macFilter = ui->macFilterEdit->text().trimmed().toUpper();
    if (!macFilter.isEmpty() && info.srcMac != macFilter && info.dstMac != macFilter) return false;

    // 类型过滤
    QString ethTypeFilter = ui->ethTypeFilterEdit->text().trimmed().toUpper();
    if (!ethTypeFilter.isEmpty() && info.ethType != ethTypeFilter) return false;

    // IP过滤
    QString ipFilter = ui->ipFilterEdit->text().trimmed();
    if (!ipFilter.isEmpty() && info.srcIp != ipFilter && info.dstIp != ipFilter) return false;

    // 协议过滤
    QString protoFilter = ui->protoFilterEdit->text().trimmed().toUpper();
    if (!protoFilter.isEmpty()) {
        QString pktProto = info.appProtocol.isEmpty() ? info.protocol : info.appProtocol;
        if (pktProto.toUpper() != protoFilter) return false;
    }

    // 端口过滤
    QString portFilter = ui->portFilterEdit->text().trimmed();
    if (!portFilter.isEmpty() && info.srcPort != portFilter && info.dstPort != portFilter) return false;

    return true;
}

void MainWindow::onFilterChanged() {
    ui->packetTable->setRowCount(0);
    rowToPacketIndex.clear();  // 清空映射表

    // 遍历所有数据包，只显示符合过滤条件的
    for (int i = 0; i < packetList.size(); i++) {
        const PacketInfo &info = packetList[i];
        if (filterPacket(info)) {
            QString displayProtocol = info.protocol;
            if (!info.appProtocol.isEmpty()) {
                displayProtocol = info.appProtocol;
            }

            int row = ui->packetTable->rowCount();
            ui->packetTable->insertRow(row);

            // 记录新的映射关系
            rowToPacketIndex[row] = i;

            ui->packetTable->setItem(row, 0, new QTableWidgetItem(QString::number(info.originalIndex)));
            ui->packetTable->setItem(row, 1, new QTableWidgetItem(info.time));
            ui->packetTable->setItem(row, 2, new QTableWidgetItem(info.srcMac));
            ui->packetTable->setItem(row, 3, new QTableWidgetItem(info.dstMac));
            ui->packetTable->setItem(row, 4, new QTableWidgetItem(info.ethType));
            ui->packetTable->setItem(row, 5, new QTableWidgetItem(info.srcIp));
            ui->packetTable->setItem(row, 6, new QTableWidgetItem(info.dstIp));
            ui->packetTable->setItem(row, 7, new QTableWidgetItem(displayProtocol));
            ui->packetTable->setItem(row, 8, new QTableWidgetItem(QString::number(info.rawData.size())));
            ui->packetTable->setItem(row, 9, new QTableWidgetItem(info.info));
        }
    }
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    // 动态调整packetTable所有列宽
    int tableWidth = ui->packetTable->viewport()->width();
    int columnCount = ui->packetTable->columnCount();
    if (columnCount == 0) return;
    // 比例分配每列宽度（可根据实际需求调整比例）
    // 这里按初始宽度比例分配
    QVector<int> initWidths = {60, 100, 150, 150, 80, 120, 120, 80, 60, 300};
    int totalInit = 0;
    for (int w : initWidths) totalInit += w;
    for (int i = 0; i < columnCount && i < initWidths.size(); ++i) {
        int colWidth = tableWidth * initWidths[i] / totalInit;
        ui->packetTable->setColumnWidth(i, colWidth);
    }
}
