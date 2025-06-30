#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "PacketCaptureThread/packetcapturethread.h"
#include "ProtocolParse/protocolparser.h"
#include "ProtocolTreeItem/protocoltreeitem.h"
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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , captureThread(nullptr)
    , protocolParser(new ProtocolParser())
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
    delete protocolParser;
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

// 解析并显示数据包
void MainWindow::parseAndDisplayPacket(const QByteArray &data) {
    PacketInfo info;
    info.rawData = data;
    info.time = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    info.originalIndex = packetList.size() + 1;  // 设置原始序号（从1开始）

    // 使用协议解析器解析数据包
    if (!protocolParser->parsePacket(data, info)) {
        return;
    }

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
                protocolParser->parseHTTP(info.rawData, info.fields["app_data"].offset, info.fields["app_data"].length, app);
            } else if (info.appProtocol == "DNS") {
                protocolParser->parseDNS(info.rawData, info.fields["app_data"].offset, info.fields["app_data"].length, app);
            } else if (info.appProtocol == "DHCP") {
                protocolParser->parseDHCP(info.rawData, info.fields["app_data"].offset, info.fields["app_data"].length, app);
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

        item = new ProtocolTreeItem(QStringList() << QString("发送方MAC: %1").arg(ProtocolParser::macToString(arpData + 8)));
        item->setFieldInfo(info.fields["arp_sha"].offset, 6, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("发送方IP: %1").arg(ProtocolParser::ipToString(arpData + 14)));
        item->setFieldInfo(info.fields["arp_spa"].offset, 4, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("目标MAC: %1").arg(ProtocolParser::macToString(arpData + 18)));
        item->setFieldInfo(info.fields["arp_tha"].offset, 6, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("目标IP: %1").arg(ProtocolParser::ipToString(arpData + 24)));
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
