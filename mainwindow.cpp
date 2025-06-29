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
    // HTTP (端口 80, 8080)
    static const QList<QByteArray> httpMethods = {"GET ", "POST", "HTTP", "HEAD", "PUT ", "OPTI", "DELE", "PATC", "TRAC", "CONN"};
    if (srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080) {
        if (data.size() > offset + 4) {
            QByteArray header = data.mid(offset, 4);
            bool isHttp = false;
            for (const auto &method : httpMethods) {
                if (header.startsWith(method)) {
                    isHttp = true;
                    break;
                }
            }
            // 响应行：HTTP/1.x 20x/30x/40x/50x
            if (!isHttp && data.size() > offset + 8) {
                QByteArray resp = data.mid(offset, 5);
                if (resp == "HTTP/") isHttp = true;
            }
            if (isHttp) return "HTTP";
        }
    }

    // HTTPS/TLS (端口 443)
    if (srcPort == 443 || dstPort == 443) {
        // TLS ClientHello/ServerHello通常以0x16开头，且长度大于5
        if (data.size() > offset + 5) {
            const uchar *tls = (const uchar*)data.constData() + offset;
            if (tls[0] == 0x16 && (tls[1] == 0x03) && (tls[2] >= 0x00 && tls[2] <= 0x03)) {
                // 0x16: Handshake, 0x03 0x01/0x02/0x03: TLS version
                return "HTTPS/TLS";
            }
        }
        // 其它情况不标记为HTTPS/TLS，避免误判
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
    info.fields["eth_header"] = {0, 14, LAYER_ETHERNET};
    info.fields["eth_dst"] = {0, 6, LAYER_ETHERNET};
    info.fields["eth_src"] = {6, 6, LAYER_ETHERNET};
    info.fields["eth_type"] = {12, 2, LAYER_ETHERNET};

    int ipOffset = 14;

    if (ethType == 0x0800 && data.size() >= ipOffset+20) { // IPv4
        const uchar *ip = d + ipOffset;
        int ipHeaderLen = (ip[0]&0x0F)*4;
        if (data.size() < ipOffset + ipHeaderLen) return; // IP头部长度检查
        info.srcIp = ipToString(ip + 12);
        info.dstIp = ipToString(ip + 16);
        quint8 proto = ip[9];

        // 存储IP层字段位置
        info.fields["ip_header"] = {ipOffset, ipHeaderLen, LAYER_IP};
        info.fields["ip_ver_ihl"] = {ipOffset, 1, LAYER_IP};
        info.fields["ip_tos"] = {ipOffset + 1, 1, LAYER_IP};
        info.fields["ip_len"] = {ipOffset + 2, 2, LAYER_IP};
        info.fields["ip_id"] = {ipOffset + 4, 2, LAYER_IP};
        info.fields["ip_flags_frag"] = {ipOffset + 6, 2, LAYER_IP};
        info.fields["ip_ttl"] = {ipOffset + 8, 1, LAYER_IP};
        info.fields["ip_proto"] = {ipOffset + 9, 1, LAYER_IP};
        info.fields["ip_checksum"] = {ipOffset + 10, 2, LAYER_IP};
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
            int tcpHeaderLen = (tcp[12]>>4) * 4;
            if (data.size() < transportOffset + tcpHeaderLen) return; // TCP头部长度检查
            quint16 srcPort = (tcp[0]<<8)|tcp[1];
            quint16 dstPort = (tcp[2]<<8)|tcp[3];
            info.srcPort = QString::number(srcPort);
            info.dstPort = QString::number(dstPort);

            // 存储TCP层字段位置
            info.fields["tcp_header"] = {transportOffset, tcpHeaderLen, LAYER_TRANSPORT};
            info.fields["tcp_srcport"] = {transportOffset, 2, LAYER_TRANSPORT};
            info.fields["tcp_dstport"] = {transportOffset + 2, 2, LAYER_TRANSPORT};
            info.fields["tcp_seq"] = {transportOffset + 4, 4, LAYER_TRANSPORT};
            info.fields["tcp_ack"] = {transportOffset + 8, 4, LAYER_TRANSPORT};
            info.fields["tcp_hdr_flags"] = {transportOffset + 12, 2, LAYER_TRANSPORT};
            info.fields["tcp_window"] = {transportOffset + 14, 2, LAYER_TRANSPORT};
            info.fields["tcp_checksum"] = {transportOffset + 16, 2, LAYER_TRANSPORT};
            info.fields["tcp_urgent"] = {transportOffset + 18, 2, LAYER_TRANSPORT};

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
            if (data.size() < transportOffset + 8) return; // UDP头部长度检查
            quint16 srcPort = (udp[0]<<8)|udp[1];
            quint16 dstPort = (udp[2]<<8)|udp[3];
            info.srcPort = QString::number(srcPort);
            info.dstPort = QString::number(dstPort);

            // 存储UDP层字段位置
            info.fields["udp_header"] = {transportOffset, 8, LAYER_TRANSPORT};
            info.fields["udp_srcport"] = {transportOffset, 2, LAYER_TRANSPORT};
            info.fields["udp_dstport"] = {transportOffset + 2, 2, LAYER_TRANSPORT};
            info.fields["udp_len"] = {transportOffset + 4, 2, LAYER_TRANSPORT};
            info.fields["udp_checksum"] = {transportOffset + 6, 2, LAYER_TRANSPORT};

            // 解析应用层协议
            int appOffset = transportOffset + 8;
            if (data.size() > appOffset) {
                info.appProtocol = parseApplicationProtocol(data, appOffset, srcPort, dstPort, info);
                if (!info.appProtocol.isEmpty()) {
                    info.fields["app_data"] = {appOffset, data.size() - appOffset, LAYER_APPLICATION};
                }
            }
        } else if (proto == 1 && data.size() >= transportOffset + 8) { // ICMP
            if (data.size() < transportOffset + 8) return; // ICMP头部长度检查
            info.fields["icmp_header"] = {transportOffset, 8, LAYER_TRANSPORT};
            info.fields["icmp_type"] = {transportOffset, 1, LAYER_TRANSPORT};
            info.fields["icmp_code"] = {transportOffset + 1, 1, LAYER_TRANSPORT};
            info.fields["icmp_checksum"] = {transportOffset + 2, 2, LAYER_TRANSPORT};
            info.fields["icmp_data"] = {transportOffset + 4, 4, LAYER_TRANSPORT};
        }
    } else if (ethType == 0x0806 && data.size() >= ipOffset+28) { // ARP
        if (data.size() < ipOffset + 28) return; // ARP长度检查
        info.protocol = "ARP";
        info.fields["arp_packet"] = {ipOffset, 28, LAYER_IP};
        info.fields["arp_htype"] = {ipOffset, 2, LAYER_IP};
        info.fields["arp_ptype"] = {ipOffset + 2, 2, LAYER_IP};
        info.fields["arp_hlen"] = {ipOffset + 4, 1, LAYER_IP};
        info.fields["arp_plen"] = {ipOffset + 5, 1, LAYER_IP};
        info.fields["arp_op"] = {ipOffset + 6, 2, LAYER_IP};
        info.fields["arp_sha"] = {ipOffset + 8, 6, LAYER_IP};
        info.fields["arp_spa"] = {ipOffset + 14, 4, LAYER_IP};
        info.fields["arp_tha"] = {ipOffset + 18, 6, LAYER_IP};
        info.fields["arp_tpa"] = {ipOffset + 24, 4, LAYER_IP};
    } else if (ethType == 0x86DD && data.size() >= ipOffset+40) { // IPv6
        if (data.size() < ipOffset + 40) return; // IPv6头部长度检查
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
    currentPacketIndex = row;  // 保存当前选中的数据包索引
    const PacketInfo &info = packetList[row];
    updateProtocolTree(info);
    updateRawDataView(info.rawData, -1, 0); // 显示原始数据，不高亮
}

void MainWindow::onProtocolTreeItemClicked(QTreeWidgetItem *item, int /*column*/) {
    if (currentPacketIndex < 0 || currentPacketIndex >= packetList.size()) return;

    ProtocolTreeItem *pItem = dynamic_cast<ProtocolTreeItem*>(item);
    if (pItem && pItem->getFieldOffset() >= 0) {
        const PacketInfo &info = packetList[currentPacketIndex];  // 使用当前选中的数据包
        updateRawDataView(info.rawData, pItem->getFieldOffset(),
                          pItem->getFieldLength(), pItem->getFieldLayer());
    }
}

void MainWindow::parseHTTP(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    if (data.size() <= offset) return;

    QString httpData = QString::fromUtf8(data.mid(offset, qMin(2000, data.size() - offset)));
    QStringList lines = httpData.split("\r\n");

    int currentOffset = offset;
    for (int i = 0; i < lines.size(); i++) {
        if (lines[i].isEmpty()) {
            // 空行表示HTTP头部结束
            currentOffset += 2;

            // 显示HTTP Body的前100字节
            if (data.size() > currentOffset) {
                ProtocolTreeItem *body = new ProtocolTreeItem(QStringList() << "HTTP Body");
                body->setFieldInfo(currentOffset, data.size() - currentOffset, LAYER_APPLICATION);
                parent->addChild(body);

                QString bodyPreview = QString::fromUtf8(data.mid(currentOffset, qMin(100, data.size() - currentOffset)));
                bodyPreview.replace("\r", "\\r").replace("\n", "\\n");
                if (data.size() - currentOffset > 100) {
                    bodyPreview += "...";
                }
                ProtocolTreeItem *preview = new ProtocolTreeItem(QStringList() << QString("Data: %1").arg(bodyPreview));
                preview->setFieldInfo(currentOffset, qMin(100, data.size() - currentOffset), LAYER_APPLICATION);
                body->addChild(preview);
            }
            break;
        } else {
            ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << lines[i]);
            item->setFieldInfo(currentOffset, lines[i].toUtf8().length(), LAYER_APPLICATION);
            parent->addChild(item);
            currentOffset += lines[i].toUtf8().length() + 2; // +2 for \r\n
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
    quint16 authority = (dns[8] << 8) | dns[9];
    quint16 additional = (dns[10] << 8) | dns[11];

    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("Transaction ID: 0x%1").arg(transId, 4, 16, QChar('0')));
    item->setFieldInfo(offset, 2, LAYER_APPLICATION);
    parent->addChild(item);

    // 解析Flags
    ProtocolTreeItem *flagsItem = new ProtocolTreeItem(QStringList() << QString("Flags: 0x%1").arg(flags, 4, 16, QChar('0')));
    flagsItem->setFieldInfo(offset + 2, 2, LAYER_APPLICATION);
    parent->addChild(flagsItem);

    // Flags详细信息
    bool qr = (flags >> 15) & 1;
    int opcode = (flags >> 11) & 0xF;
    bool aa = (flags >> 10) & 1;
    bool tc = (flags >> 9) & 1;
    bool rd = (flags >> 8) & 1;
    bool ra = (flags >> 7) & 1;
    int rcode = flags & 0xF;

    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Response: %1").arg(qr ? "Response" : "Query")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Opcode: %1").arg(opcode)));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Authoritative Answer: %1").arg(aa ? "Yes" : "No")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Truncated: %1").arg(tc ? "Yes" : "No")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Recursion Desired: %1").arg(rd ? "Yes" : "No")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Recursion Available: %1").arg(ra ? "Yes" : "No")));
    flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Response Code: %1").arg(rcode)));

    item = new ProtocolTreeItem(QStringList() << QString("Questions: %1").arg(questions));
    item->setFieldInfo(offset + 4, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Answer RRs: %1").arg(answers));
    item->setFieldInfo(offset + 6, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Authority RRs: %1").arg(authority));
    item->setFieldInfo(offset + 8, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Additional RRs: %1").arg(additional));
    item->setFieldInfo(offset + 10, 2, LAYER_APPLICATION);
    parent->addChild(item);
}

void MainWindow::parseDHCP(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
    if (data.size() < offset + 240) return;

    const uchar *dhcp = (const uchar*)data.constData() + offset;
    quint8 op = dhcp[0];
    quint8 htype = dhcp[1];
    quint8 hlen = dhcp[2];
    quint8 hops = dhcp[3];
    quint32 xid = (dhcp[4] << 24) | (dhcp[5] << 16) | (dhcp[6] << 8) | dhcp[7];
    quint16 secs = (dhcp[8] << 8) | dhcp[9];
    quint16 flags = (dhcp[10] << 8) | dhcp[11];

    ProtocolTreeItem *item = new ProtocolTreeItem(QStringList() << QString("Message Type: %1 (%2)")
                                                                       .arg(op).arg(op == 1 ? "Boot Request" : "Boot Reply"));
    item->setFieldInfo(offset, 1, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Hardware Type: %1 (Ethernet)").arg(htype));
    item->setFieldInfo(offset + 1, 1, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Hardware Address Length: %1").arg(hlen));
    item->setFieldInfo(offset + 2, 1, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Hops: %1").arg(hops));
    item->setFieldInfo(offset + 3, 1, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Transaction ID: 0x%1").arg(xid, 8, 16, QChar('0')));
    item->setFieldInfo(offset + 4, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Seconds elapsed: %1").arg(secs));
    item->setFieldInfo(offset + 8, 2, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Flags: 0x%1").arg(flags, 4, 16, QChar('0')));
    item->setFieldInfo(offset + 10, 2, LAYER_APPLICATION);
    parent->addChild(item);

    // IP addresses
    item = new ProtocolTreeItem(QStringList() << QString("Client IP: %1").arg(ipToString(dhcp + 12)));
    item->setFieldInfo(offset + 12, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Your IP: %1").arg(ipToString(dhcp + 16)));
    item->setFieldInfo(offset + 16, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Server IP: %1").arg(ipToString(dhcp + 20)));
    item->setFieldInfo(offset + 20, 4, LAYER_APPLICATION);
    parent->addChild(item);

    item = new ProtocolTreeItem(QStringList() << QString("Gateway IP: %1").arg(ipToString(dhcp + 24)));
    item->setFieldInfo(offset + 24, 4, LAYER_APPLICATION);
    parent->addChild(item);

    // Client hardware address
    item = new ProtocolTreeItem(QStringList() << QString("Client MAC: %1").arg(macToString(dhcp + 28)));
    item->setFieldInfo(offset + 28, 16, LAYER_APPLICATION);
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
    if (!info.srcIp.isEmpty() && info.fields.contains("ip_header")) {
        const uchar *ipHeader = (const uchar*)info.rawData.constData() + info.fields["ip_header"].offset;

        ProtocolTreeItem *ip = new ProtocolTreeItem(QStringList() << "Internet Protocol Version 4");
        ip->setFieldInfo(info.fields["ip_header"].offset, info.fields["ip_header"].length, LAYER_IP);

        // IP版本和头部长度
        quint8 ver_ihl = ipHeader[0];
        item = new ProtocolTreeItem(QStringList() << QString("Version: %1").arg(ver_ihl >> 4));
        item->setFieldInfo(info.fields["ip_ver_ihl"].offset, 1, LAYER_IP);
        ip->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Header Length: %1 bytes").arg((ver_ihl & 0x0F) * 4));
        item->setFieldInfo(info.fields["ip_ver_ihl"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 服务类型
        quint8 tos = ipHeader[1];
        item = new ProtocolTreeItem(QStringList() << QString("Type of Service: 0x%1").arg(tos, 2, 16, QChar('0')));
        item->setFieldInfo(info.fields["ip_tos"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 总长度
        quint16 totalLen = (ipHeader[2] << 8) | ipHeader[3];
        item = new ProtocolTreeItem(QStringList() << QString("Total Length: %1 bytes").arg(totalLen));
        item->setFieldInfo(info.fields["ip_len"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // 标识
        quint16 id = (ipHeader[4] << 8) | ipHeader[5];
        item = new ProtocolTreeItem(QStringList() << QString("Identification: 0x%1 (%2)").arg(id, 4, 16, QChar('0')).arg(id));
        item->setFieldInfo(info.fields["ip_id"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // 标志和片偏移
        quint16 flags_frag = (ipHeader[6] << 8) | ipHeader[7];
        quint8 flags = (flags_frag >> 13) & 0x07;
        quint16 fragOffset = flags_frag & 0x1FFF;

        ProtocolTreeItem *flagsItem = new ProtocolTreeItem(QStringList() << QString("Flags: 0x%1").arg(flags, 1, 16));
        flagsItem->setFieldInfo(info.fields["ip_flags_frag"].offset, 2, LAYER_IP);
        ip->addChild(flagsItem);

        flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Reserved: %1").arg((flags >> 2) & 1)));
        flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("Don't Fragment: %1").arg((flags >> 1) & 1)));
        flagsItem->addChild(new QTreeWidgetItem(QStringList() << QString("More Fragments: %1").arg(flags & 1)));

        item = new ProtocolTreeItem(QStringList() << QString("Fragment Offset: %1").arg(fragOffset));
        item->setFieldInfo(info.fields["ip_flags_frag"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // TTL
        item = new ProtocolTreeItem(QStringList() << QString("Time to Live: %1").arg(ipHeader[8]));
        item->setFieldInfo(info.fields["ip_ttl"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 协议
        item = new ProtocolTreeItem(QStringList() << QString("Protocol: %1 (%2)").arg(info.protocol).arg(ipHeader[9]));
        item->setFieldInfo(info.fields["ip_proto"].offset, 1, LAYER_IP);
        ip->addChild(item);

        // 校验和
        quint16 checksum = (ipHeader[10] << 8) | ipHeader[11];
        item = new ProtocolTreeItem(QStringList() << QString("Header Checksum: 0x%1").arg(checksum, 4, 16, QChar('0')));
        item->setFieldInfo(info.fields["ip_checksum"].offset, 2, LAYER_IP);
        ip->addChild(item);

        // 源IP和目的IP
        item = new ProtocolTreeItem(QStringList() << ("Source: " + info.srcIp));
        item->setFieldInfo(info.fields["ip_src"].offset, 4, LAYER_IP);
        ip->addChild(item);

        item = new ProtocolTreeItem(QStringList() << ("Destination: " + info.dstIp));
        item->setFieldInfo(info.fields["ip_dst"].offset, 4, LAYER_IP);
        ip->addChild(item);

        ui->protocolTree->addTopLevelItem(ip);

        // 传输层
        if (info.protocol == "TCP" && info.fields.contains("tcp_header")) {
            const uchar *tcpHeader = (const uchar*)info.rawData.constData() + info.fields["tcp_header"].offset;

            ProtocolTreeItem *tcp = new ProtocolTreeItem(QStringList() << "Transmission Control Protocol");
            tcp->setFieldInfo(info.fields["tcp_header"].offset, info.fields["tcp_header"].length, LAYER_TRANSPORT);

            // 源端口和目的端口
            item = new ProtocolTreeItem(QStringList() << ("Source Port: " + info.srcPort));
            item->setFieldInfo(info.fields["tcp_srcport"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            item = new ProtocolTreeItem(QStringList() << ("Destination Port: " + info.dstPort));
            item->setFieldInfo(info.fields["tcp_dstport"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 序列号
            quint32 seq = (tcpHeader[4] << 24) | (tcpHeader[5] << 16) | (tcpHeader[6] << 8) | tcpHeader[7];
            item = new ProtocolTreeItem(QStringList() << QString("Sequence Number: %1").arg(seq));
            item->setFieldInfo(info.fields["tcp_seq"].offset, 4, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 确认号
            quint32 ack = (tcpHeader[8] << 24) | (tcpHeader[9] << 16) | (tcpHeader[10] << 8) | tcpHeader[11];
            item = new ProtocolTreeItem(QStringList() << QString("Acknowledgment Number: %1").arg(ack));
            item->setFieldInfo(info.fields["tcp_ack"].offset, 4, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 头部长度和标志
            quint8 hdrLen = (tcpHeader[12] >> 4) * 4;
            quint8 flags = tcpHeader[13];

            item = new ProtocolTreeItem(QStringList() << QString("Header Length: %1 bytes").arg(hdrLen));
            item->setFieldInfo(info.fields["tcp_hdr_flags"].offset, 1, LAYER_TRANSPORT);
            tcp->addChild(item);

            ProtocolTreeItem *flagsItem = new ProtocolTreeItem(QStringList() << QString("Flags: 0x%1").arg(flags, 2, 16, QChar('0')));
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
            item = new ProtocolTreeItem(QStringList() << QString("Window Size: %1").arg(window));
            item->setFieldInfo(info.fields["tcp_window"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 校验和
            quint16 checksum = (tcpHeader[16] << 8) | tcpHeader[17];
            item = new ProtocolTreeItem(QStringList() << QString("Checksum: 0x%1").arg(checksum, 4, 16, QChar('0')));
            item->setFieldInfo(info.fields["tcp_checksum"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            // 紧急指针
            quint16 urgent = (tcpHeader[18] << 8) | tcpHeader[19];
            item = new ProtocolTreeItem(QStringList() << QString("Urgent Pointer: %1").arg(urgent));
            item->setFieldInfo(info.fields["tcp_urgent"].offset, 2, LAYER_TRANSPORT);
            tcp->addChild(item);

            ui->protocolTree->addTopLevelItem(tcp);

        } else if (info.protocol == "UDP" && info.fields.contains("udp_header")) {
            const uchar *udpHeader = (const uchar*)info.rawData.constData() + info.fields["udp_header"].offset;

            ProtocolTreeItem *udp = new ProtocolTreeItem(QStringList() << "User Datagram Protocol");
            udp->setFieldInfo(info.fields["udp_header"].offset, info.fields["udp_header"].length, LAYER_TRANSPORT);

            item = new ProtocolTreeItem(QStringList() << ("Source Port: " + info.srcPort));
            item->setFieldInfo(info.fields["udp_srcport"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            item = new ProtocolTreeItem(QStringList() << ("Destination Port: " + info.dstPort));
            item->setFieldInfo(info.fields["udp_dstport"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            quint16 len = (udpHeader[4] << 8) | udpHeader[5];
            item = new ProtocolTreeItem(QStringList() << QString("Length: %1 bytes").arg(len));
            item->setFieldInfo(info.fields["udp_len"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            quint16 checksum = (udpHeader[6] << 8) | udpHeader[7];
            item = new ProtocolTreeItem(QStringList() << QString("Checksum: 0x%1").arg(checksum, 4, 16, QChar('0')));
            item->setFieldInfo(info.fields["udp_checksum"].offset, 2, LAYER_TRANSPORT);
            udp->addChild(item);

            ui->protocolTree->addTopLevelItem(udp);

        } else if (info.protocol == "ICMP" && info.fields.contains("icmp_header")) {
            const uchar *icmpHeader = (const uchar*)info.rawData.constData() + info.fields["icmp_header"].offset;

            ProtocolTreeItem *icmp = new ProtocolTreeItem(QStringList() << "Internet Control Message Protocol");
            icmp->setFieldInfo(info.fields["icmp_header"].offset, info.fields["icmp_header"].length, LAYER_TRANSPORT);

            quint8 type = icmpHeader[0];
            quint8 code = icmpHeader[1];

            QString typeStr;
            switch(type) {
            case 0: typeStr = "Echo Reply"; break;
            case 3: typeStr = "Destination Unreachable"; break;
            case 8: typeStr = "Echo Request"; break;
            case 11: typeStr = "Time Exceeded"; break;
            default: typeStr = QString::number(type);
            }

            item = new ProtocolTreeItem(QStringList() << QString("Type: %1 (%2)").arg(type).arg(typeStr));
            item->setFieldInfo(info.fields["icmp_type"].offset, 1, LAYER_TRANSPORT);
            icmp->addChild(item);

            item = new ProtocolTreeItem(QStringList() << QString("Code: %1").arg(code));
            item->setFieldInfo(info.fields["icmp_code"].offset, 1, LAYER_TRANSPORT);
            icmp->addChild(item);

            quint16 checksum = (icmpHeader[2] << 8) | icmpHeader[3];
            item = new ProtocolTreeItem(QStringList() << QString("Checksum: 0x%1").arg(checksum, 4, 16, QChar('0')));
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
                parseHTTP(info.rawData, info.fields["app_data"].offset, const_cast<PacketInfo&>(info), app);
            } else if (info.appProtocol == "DNS") {
                parseDNS(info.rawData, info.fields["app_data"].offset, const_cast<PacketInfo&>(info), app);
            } else if (info.appProtocol == "DHCP") {
                parseDHCP(info.rawData, info.fields["app_data"].offset, const_cast<PacketInfo&>(info), app);
            } else if (info.appProtocol == "HTTPS/TLS") {
                // 简单显示TLS提示
                ProtocolTreeItem *tlsInfo = new ProtocolTreeItem(QStringList() << "TLS/SSL数据 (未详细解析)");
                tlsInfo->setFieldInfo(info.fields["app_data"].offset, info.fields["app_data"].length, LAYER_APPLICATION);
                app->addChild(tlsInfo);
            }

            ui->protocolTree->addTopLevelItem(app);
        }
    } else if (info.protocol == "ARP" && info.fields.contains("arp_packet")) {
        const uchar *arpData = (const uchar*)info.rawData.constData() + info.fields["arp_packet"].offset;

        ProtocolTreeItem *arp = new ProtocolTreeItem(QStringList() << "Address Resolution Protocol");
        arp->setFieldInfo(info.fields["arp_packet"].offset, info.fields["arp_packet"].length, LAYER_IP);

        quint16 htype = (arpData[0] << 8) | arpData[1];
        item = new ProtocolTreeItem(QStringList() << QString("Hardware Type: %1 (Ethernet)").arg(htype));
        item->setFieldInfo(info.fields["arp_htype"].offset, 2, LAYER_IP);
        arp->addChild(item);

        quint16 ptype = (arpData[2] << 8) | arpData[3];
        item = new ProtocolTreeItem(QStringList() << QString("Protocol Type: 0x%1 (IPv4)").arg(ptype, 4, 16, QChar('0')));
        item->setFieldInfo(info.fields["arp_ptype"].offset, 2, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Hardware Size: %1").arg(arpData[4]));
        item->setFieldInfo(info.fields["arp_hlen"].offset, 1, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Protocol Size: %1").arg(arpData[5]));
        item->setFieldInfo(info.fields["arp_plen"].offset, 1, LAYER_IP);
        arp->addChild(item);

        quint16 op = (arpData[6] << 8) | arpData[7];
        QString opStr = (op == 1) ? "Request" : (op == 2) ? "Reply" : "Unknown";
        item = new ProtocolTreeItem(QStringList() << QString("Opcode: %1 (%2)").arg(op).arg(opStr));
        item->setFieldInfo(info.fields["arp_op"].offset, 2, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Sender MAC: %1").arg(macToString(arpData + 8)));
        item->setFieldInfo(info.fields["arp_sha"].offset, 6, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Sender IP: %1").arg(ipToString(arpData + 14)));
        item->setFieldInfo(info.fields["arp_spa"].offset, 4, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Target MAC: %1").arg(macToString(arpData + 18)));
        item->setFieldInfo(info.fields["arp_tha"].offset, 6, LAYER_IP);
        arp->addChild(item);

        item = new ProtocolTreeItem(QStringList() << QString("Target IP: %1").arg(ipToString(arpData + 24)));
        item->setFieldInfo(info.fields["arp_tpa"].offset, 4, LAYER_IP);
        arp->addChild(item);

        ui->protocolTree->addTopLevelItem(arp);
    }

    ui->protocolTree->expandAll();
}

void MainWindow::updateRawDataView(const QByteArray &data, int highlightStart, int highlightLen, ProtocolLayer layer) {
    ui->rawDataEdit->clear();

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
