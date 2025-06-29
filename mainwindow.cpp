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

    // 初始化协议层颜色
    initLayerColors();

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

    // 设置表头自适应
    ui->packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 设置原始数据视图字体
    QFont monoFont("Consolas");
    monoFont.setStyleHint(QFont::Monospace);
    ui->rawDataEdit->setFont(monoFont);
}

MainWindow::~MainWindow() {
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
    }
    delete ui;
}

void MainWindow::initLayerColors() {
    layerColors[LAYER_ETHERNET] = QColor(255, 240, 240);    // 浅红
    layerColors[LAYER_IP] = QColor(240, 255, 240);          // 浅绿
    layerColors[LAYER_TRANSPORT] = QColor(240, 240, 255);   // 浅蓝
    layerColors[LAYER_APPLICATION] = QColor(255, 255, 240); // 浅黄
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
}

void MainWindow::onPacketCaptured(const QByteArray &data, const struct pcap_pkthdr *header) {
    parseAndDisplayPacket(data, header);
}

QString MainWindow::macToString(const uchar *mac) {
    return QString("%1-%2-%3-%4-%5-%6")
    .arg(mac[0],2,16,QChar('0'))
        .arg(mac[1],2,16,QChar('0'))
        .arg(mac[2],2,16,QChar('0'))
        .arg(mac[3],2,16,QChar('0'))
        .arg(mac[4],2,16,QChar('0'))
        .arg(mac[5],2,16,QChar('0')).toUpper();
}

QString MainWindow::ipToString(const uchar *ip) {
    return QString("%1.%2.%3.%4").arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
}

// 解析应用层协议
QString MainWindow::parseApplicationProtocol(const QByteArray &data, int offset, quint16 srcPort, quint16 dstPort, PacketInfo &info) {
    // HTTP (端口 80, 8080, 443)
    if (srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080) {
        if (data.size() > offset + 4) {
            QByteArray header = data.mid(offset, 4);
            if (header == "GET " || header == "POST" || header == "HTTP" || header == "HEAD" || header == "PUT ") {
                return "HTTP";
            }
        }
    }

    // HTTPS
    if (srcPort == 443 || dstPort == 443) {
        return "HTTPS";
    }

    // DNS (端口 53)
    if (srcPort == 53 || dstPort == 53) {
        return "DNS";
    }

    // DHCP (端口 67, 68)
    if ((srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67)) {
        return "DHCP";
    }

    // FTP (端口 21, 20)
    if (srcPort == 21 || dstPort == 21) {
        return "FTP-Control";
    }
    if (srcPort == 20 || dstPort == 20) {
        return "FTP-Data";
    }

    // SSH (端口 22)
    if (srcPort == 22 || dstPort == 22) {
        return "SSH";
    }

    // Telnet (端口 23)
    if (srcPort == 23 || dstPort == 23) {
        return "Telnet";
    }

    // SMTP (端口 25)
    if (srcPort == 25 || dstPort == 25) {
        return "SMTP";
    }

    // POP3 (端口 110)
    if (srcPort == 110 || dstPort == 110) {
        return "POP3";
    }

    // IMAP (端口 143)
    if (srcPort == 143 || dstPort == 143) {
        return "IMAP";
    }

    return "";
}

// 解析以太网/IP/TCP/UDP/ICMP头部，填充PacketInfo
void MainWindow::parseAndDisplayPacket(const QByteArray &data, const struct pcap_pkthdr *header) {
    if (data.size() < 14) return; // 以太网头部最小14字节

    PacketInfo info;
    info.rawData = data;
    info.time = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");

    // 以太网头
    const uchar *d = (const uchar*)data.constData();
    info.dstMac = macToString(d);
    info.srcMac = macToString(d + 6);
    quint16 ethType = (d[12]<<8) | d[13];
    info.ethType = QString("0x%1").arg(ethType,4,16,QChar('0')).toUpper();

    // 存储以太网层字段位置
    info.fields["eth_dst"] = {0, 6, LAYER_ETHERNET};
    info.fields["eth_src"] = {6, 6, LAYER_ETHERNET};
    info.fields["eth_type"] = {12, 2, LAYER_ETHERNET};

    int ipOffset = 14;

    if (ethType == 0x0800 && data.size() >= ipOffset+20) { // IPv4
        const uchar *ip = d + ipOffset;
        int ipHeaderLen = (ip[0]&0x0F)*4;
        info.srcIp = ipToString(ip + 12);
        info.dstIp = ipToString(ip + 16);
        quint8 proto = ip[9];

        // 存储IP层字段位置
        info.fields["ip_header"] = {ipOffset, ipHeaderLen, LAYER_IP};
        info.fields["ip_src"] = {ipOffset + 12, 4, LAYER_IP};
        info.fields["ip_dst"] = {ipOffset + 16, 4, LAYER_IP};

        switch(proto) {
        case 1: info.protocol = "ICMP"; break;
        case 6: info.protocol = "TCP"; break;
        case 17: info.protocol = "UDP"; break;
        default: info.protocol = QString("IP-Proto-%1").arg(proto); break;
        }

        int transportOffset = ipOffset + ipHeaderLen;

        if (proto == 6 && data.size() >= transportOffset + 20) { // TCP
            const uchar *tcp = d + transportOffset;
            quint16 srcPort = (tcp[0]<<8)|tcp[1];
            quint16 dstPort = (tcp[2]<<8)|tcp[3];
            info.srcPort = QString::number(srcPort);
            info.dstPort = QString::number(dstPort);
            int tcpHeaderLen = (tcp[12]>>4) * 4;

            // 存储TCP层字段位置
            info.fields["tcp_header"] = {transportOffset, tcpHeaderLen, LAYER_TRANSPORT};
            info.fields["tcp_srcport"] = {transportOffset, 2, LAYER_TRANSPORT};
            info.fields["tcp_dstport"] = {transportOffset + 2, 2, LAYER_TRANSPORT};

            // 解析应用层协议
            int appOffset = transportOffset + tcpHeaderLen;
            if (data.size() > appOffset) {
                info.appProtocol = parseApplicationProtocol(data, appOffset, srcPort, dstPort, info);
                if (!info.appProtocol.isEmpty()) {
                    info.fields["app_data"] = {appOffset, data.size() - appOffset, LAYER_APPLICATION};
                }
            }

        } else if (proto == 17 && data.size() >= transportOffset + 8) { // UDP
            const uchar *udp = d + transportOffset;
            quint16 srcPort = (udp[0]<<8)|udp[1];
            quint16 dstPort = (udp[2]<<8)|udp[3];
            info.srcPort = QString::number(srcPort);
            info.dstPort = QString::number(dstPort);

            // 存储UDP层字段位置
            info.fields["udp_header"] = {transportOffset, 8, LAYER_TRANSPORT};
            info.fields["udp_srcport"] = {transportOffset, 2, LAYER_TRANSPORT};
            info.fields["udp_dstport"] = {transportOffset + 2, 2, LAYER_TRANSPORT};

            // 解析应用层协议
            int appOffset = transportOffset + 8;
            if (data.size() > appOffset) {
                info.appProtocol = parseApplicationProtocol(data, appOffset, srcPort, dstPort, info);
                if (!info.appProtocol.isEmpty()) {
                    info.fields["app_data"] = {appOffset, data.size() - appOffset, LAYER_APPLICATION};
                }
            }
        } else if (proto == 1 && data.size() >= transportOffset + 8) { // ICMP
            info.fields["icmp_header"] = {transportOffset, 8, LAYER_TRANSPORT};
        }
    } else if (ethType == 0x0806 && data.size() >= ipOffset+28) { // ARP
        info.protocol = "ARP";
        info.fields["arp_packet"] = {ipOffset, 28, LAYER_IP};
    } else if (ethType == 0x86DD && data.size() >= ipOffset+40) { // IPv6
        info.protocol = "IPv6";
        info.fields["ipv6_header"] = {ipOffset, 40, LAYER_IP};
    } else {
        info.protocol = "Other";
    }

    if (!filterPacket(info)) return;

    // 显示最终协议
    QString displayProtocol = info.protocol;
    if (!info.appProtocol.isEmpty()) {
        displayProtocol = info.appProtocol;
    }

    int row = ui->packetTable->rowCount();
    ui->packetTable->insertRow(row);
    ui->packetTable->setItem(row, 0, new QTableWidgetItem(info.time));
    ui->packetTable->setItem(row, 1, new QTableWidgetItem(info.srcMac));
    ui->packetTable->setItem(row, 2, new QTableWidgetItem(info.dstMac));
    ui->packetTable->setItem(row, 3, new QTableWidgetItem(info.ethType));
    ui->packetTable->setItem(row, 4, new QTableWidgetItem(info.srcIp));
    ui->packetTable->setItem(row, 5, new QTableWidgetItem(info.dstIp));
    ui->packetTable->setItem(row, 6, new QTableWidgetItem(displayProtocol));
    ui->packetTable->setItem(row, 7, new QTableWidgetItem(QString::number(data.size())));
    packetList.append(info);
}

void MainWindow::onPacketTableClicked(int row, int /*column*/) {
    if (row < 0 || row >= packetList.size()) return;
    const PacketInfo &info = packetList[row];
    updateProtocolTree(info);
    updateRawDataViewWithLayers(info);
}

void MainWindow::onProtocolTreeItemClicked(QTreeWidgetItem *item, int /*column*/) {
    ProtocolTreeItem *pItem = dynamic_cast<ProtocolTreeItem*>(item);
    if (pItem && pItem->getFieldOffset() >= 0) {
        updateRawDataView(packetList.last().rawData, pItem->getFieldOffset(),
                          pItem->getFieldLength(), pItem->getFieldLayer());
    }
}

void MainWindow::parseHTTP(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    QString httpData = QString::fromUtf8(data.mid(offset, qMin(1000, data.size() - offset)));
    QStringList lines = httpData.split("\r\n");

    for (int i = 0; i < qMin(10, lines.size()); i++) {
        if (!lines[i].isEmpty()) {
            ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << lines[i]);
            item->setFieldInfo(offset, lines[i].length() + 2, LAYER_APPLICATION);
            parent->addChild(item);
            offset += lines[i].length() + 2;
        }
    }
}

void MainWindow::parseDNS(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    if (data.size() < offset + 12) return;

    const uchar *dns = (const uchar*)data.constData() + offset;
    quint16 transId = (dns[0] << 8) | dns[1];
    quint16 flags = (dns[2] << 8) | dns[3];
    quint16 questions = (dns[4] << 8) | dns[5];
    quint16 answers = (dns[6] << 8) | dns[7];

    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("Transaction ID: 0x%1").arg(transId, 4, 16, QChar('0')));
    item->setFieldInfo(offset, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Flags: 0x%1").arg(flags, 4, 16, QChar('0')));
    item->setFieldInfo(offset + 2, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Questions: %1").arg(questions));
    item->setFieldInfo(offset + 4, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Answers: %1").arg(answers));
    item->setFieldInfo(offset + 6, 2, LAYER_APPLICATION);
    parent->addChild(item);
}

void MainWindow::parseDHCP(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    if (data.size() < offset + 240) return;

    const uchar *dhcp = (const uchar*)data.constData() + offset;
    quint8 op = dhcp[0];
    quint8 htype = dhcp[1];

    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("Operation: %1 (%2)")
                                                                       .arg(op).arg(op == 1 ? "Request" : "Reply"));
    item->setFieldInfo(offset, 1, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Hardware Type: %1").arg(htype));
    item->setFieldInfo(offset + 1, 1, LAYER_APPLICATION);
    parent->addChild(item);
}

void MainWindow::updateProtocolTree(const PacketInfo &info) {
    ui->protocolTree->clear();

    // 以太网层
    ProtocolTreeItem *eth = new ProtocolTreeItem(QStringList() << "Ethernet II");
    eth->setFieldInfo(0, 14, LAYER_ETHERNET);

    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << ("Destination: " + info.dstMac));
    item->setFieldInfo(0, 6, LAYER_ETHERNET);
    eth->addChild(item);

    item = new ProtocolTreeItem(QStringList() << ("Source: " + info.srcMac));
    item->setFieldInfo(6, 6, LAYER_ETHERNET);
    eth->addChild(item);

    item = new ProtocolTreeItem(QStringList() << ("Type: " + info.ethType));
    item->setFieldInfo(12, 2, LAYER_ETHERNET);
    eth->addChild(item);

    ui->protocolTree->addTopLevelItem(eth);

    // IP层
    if (!info.srcIp.isEmpty()) {
        ProtocolTreeItem *ip = new ProtocolTreeItem(QStringList() << "Internet Protocol Version 4");
        if (info.fields.contains("ip_header")) {
            ip->setFieldInfo(info.fields["ip_header"].offset, info.fields["ip_header"].length, LAYER_IP);
        }

        item = new ProtocolTreeItem(QStringList() << ("Source: " + info.srcIp));
        if (info.fields.contains("ip_src")) {
            item->setFieldInfo(info.fields["ip_src"].offset, 4, LAYER_IP);
        }
        ip->addChild(item);

        item = new ProtocolTreeItem(QStringList() << ("Destination: " + info.dstIp));
        if (info.fields.contains("ip_dst")) {
            item->setFieldInfo(info.fields["ip_dst"].offset, 4, LAYER_IP);
        }
        ip->addChild(item);

        ui->protocolTree->addTopLevelItem(ip);

        // 传输层
        if (info.protocol == "TCP" || info.protocol == "UDP") {
            ProtocolTreeItem *trans = new ProtocolTreeItem(QStringList() <<
                                                           (info.protocol == "TCP" ? "Transmission Control Protocol" : "User Datagram Protocol"));

            if (info.protocol == "TCP" && info.fields.contains("tcp_header")) {
                trans->setFieldInfo(info.fields["tcp_header"].offset, info.fields["tcp_header"].length, LAYER_TRANSPORT);
            } else if (info.protocol == "UDP" && info.fields.contains("udp_header")) {
                trans->setFieldInfo(info.fields["udp_header"].offset, info.fields["udp_header"].length, LAYER_TRANSPORT);
            }

            item = new ProtocolTreeItem(QStringList() << ("Source Port: " + info.srcPort));
            if (info.fields.contains("tcp_srcport") || info.fields.contains("udp_srcport")) {
                QString key = info.protocol == "TCP" ? "tcp_srcport" : "udp_srcport";
                item->setFieldInfo(info.fields[key].offset, 2, LAYER_TRANSPORT);
            }
            trans->addChild(item);

            item = new ProtocolTreeItem(QStringList() << ("Destination Port: " + info.dstPort));
            if (info.fields.contains("tcp_dstport") || info.fields.contains("udp_dstport")) {
                QString key = info.protocol == "TCP" ? "tcp_dstport" : "udp_dstport";
                item->setFieldInfo(info.fields[key].offset, 2, LAYER_TRANSPORT);
            }
            trans->addChild(item);

            ui->protocolTree->addTopLevelItem(trans);

            // 应用层
            if (!info.appProtocol.isEmpty() && info.fields.contains("app_data")) {
                ProtocolTreeItem *app = new ProtocolTreeItem(QStringList() << info.appProtocol);
                app->setFieldInfo(info.fields["app_data"].offset, info.fields["app_data"].length, LAYER_APPLICATION);

                // 根据不同协议添加详细解析
                if (info.appProtocol == "HTTP") {
                    parseHTTP(info.rawData, info.fields["app_data"].offset, const_cast<PacketInfo&>(info), app);
                } else if (info.appProtocol == "DNS") {
                    parseDNS(info.rawData, info.fields["app_data"].offset, const_cast<PacketInfo&>(info), app);
                } else if (info.appProtocol == "DHCP") {
                    parseDHCP(info.rawData, info.fields["app_data"].offset, const_cast<PacketInfo&>(info), app);
                }

                ui->protocolTree->addTopLevelItem(app);
            }
        } else if (info.protocol == "ICMP") {
            ProtocolTreeItem *icmp = new ProtocolTreeItem(QStringList() << "Internet Control Message Protocol");
            if (info.fields.contains("icmp_header")) {
                icmp->setFieldInfo(info.fields["icmp_header"].offset, info.fields["icmp_header"].length, LAYER_TRANSPORT);
            }
            ui->protocolTree->addTopLevelItem(icmp);
        }
    } else if (info.protocol == "ARP") {
        ProtocolTreeItem *arp = new ProtocolTreeItem(QStringList() << "Address Resolution Protocol");
        if (info.fields.contains("arp_packet")) {
            arp->setFieldInfo(info.fields["arp_packet"].offset, info.fields["arp_packet"].length, LAYER_IP);
        }
        ui->protocolTree->addTopLevelItem(arp);
    }

    ui->protocolTree->expandAll();
}

void MainWindow::updateRawDataView(const QByteArray &data, int highlightStart, int highlightLen, ProtocolLayer layer) {
    ui->rawDataEdit->clear();

    QString hex, ascii;
    QTextCursor cursor(ui->rawDataEdit->document());

    // 设置等宽字体
    QTextCharFormat monoFormat;
    QFont monoFont("Consolas", 10);
    monoFont.setStyleHint(QFont::Monospace);
    monoFormat.setFont(monoFont);

    for (int i = 0; i < data.size(); i += 16) {
        // 地址
        cursor.insertText(QString("%1  ").arg(i, 4, 16, QChar('0')).toUpper(), monoFormat);

        // 十六进制
        for (int j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                QTextCharFormat format = monoFormat;

                // 高亮选中的字节
                if (highlightStart >= 0 && i + j >= highlightStart && i + j < highlightStart + highlightLen) {
                    format.setBackground(QColor(255, 255, 0)); // 黄色高亮
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
                format.setBackground(QColor(255, 255, 0)); // 黄色高亮
                format.setFontWeight(QFont::Bold);
            }

            char c = data[i + j];
            cursor.insertText(QString(1, (c >= 32 && c <= 126) ? c : '.'), format);
        }

        cursor.insertText("\n", monoFormat);
    }
}

void MainWindow::updateRawDataViewWithLayers(const PacketInfo &info) {
    ui->rawDataEdit->clear();

    const QByteArray &data = info.rawData;
    QTextCursor cursor(ui->rawDataEdit->document());

    // 设置等宽字体
    QTextCharFormat monoFormat;
    QFont monoFont("Consolas", 10);
    monoFont.setStyleHint(QFont::Monospace);
    monoFormat.setFont(monoFont);

    // 创建字节到层的映射
    QVector<ProtocolLayer> byteLayer(data.size(), LAYER_ETHERNET);
    for (auto it = info.fields.begin(); it != info.fields.end(); ++it) {
        const ProtocolField &field = it.value();
        for (int i = field.offset; i < field.offset + field.length && i < data.size(); ++i) {
            byteLayer[i] = field.layer;
        }
    }

    for (int i = 0; i < data.size(); i += 16) {
        // 地址
        cursor.insertText(QString("%1  ").arg(i, 4, 16, QChar('0')).toUpper(), monoFormat);

        // 十六进制
        for (int j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                QTextCharFormat format = monoFormat;

                // 根据协议层设置背景色
                format.setBackground(layerColors[byteLayer[i + j]]);

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

            // 根据协议层设置背景色
            format.setBackground(layerColors[byteLayer[i + j]]);

            char c = data[i + j];
            cursor.insertText(QString(1, (c >= 32 && c <= 126) ? c : '.'), format);
        }

        cursor.insertText("\n", monoFormat);
    }

    // 添加图例
    cursor.insertText("\n图例: ", monoFormat);

    QTextCharFormat legendFormat = monoFormat;
    legendFormat.setBackground(layerColors[LAYER_ETHERNET]);
    cursor.insertText("以太网 ", legendFormat);

    legendFormat.setBackground(layerColors[LAYER_IP]);
    cursor.insertText("IP ", legendFormat);

    legendFormat.setBackground(layerColors[LAYER_TRANSPORT]);
    cursor.insertText("传输层 ", legendFormat);

    legendFormat.setBackground(layerColors[LAYER_APPLICATION]);
    cursor.insertText("应用层", legendFormat);
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
    for (const PacketInfo &info : packetList) {
        if (filterPacket(info)) {
            QString displayProtocol = info.protocol;
            if (!info.appProtocol.isEmpty()) {
                displayProtocol = info.appProtocol;
            }

            int row = ui->packetTable->rowCount();
            ui->packetTable->insertRow(row);
            ui->packetTable->setItem(row, 0, new QTableWidgetItem(info.time));
            ui->packetTable->setItem(row, 1, new QTableWidgetItem(info.srcMac));
            ui->packetTable->setItem(row, 2, new QTableWidgetItem(info.dstMac));
            ui->packetTable->setItem(row, 3, new QTableWidgetItem(info.ethType));
            ui->packetTable->setItem(row, 4, new QTableWidgetItem(info.srcIp));
            ui->packetTable->setItem(row, 5, new QTableWidgetItem(info.dstIp));
            ui->packetTable->setItem(row, 6, new QTableWidgetItem(displayProtocol));
            ui->packetTable->setItem(row, 7, new QTableWidgetItem(QString::number(info.rawData.size())));
        }
    }
}
