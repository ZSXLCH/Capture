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
//#include <QNetworkInterface>
//#include <QHostAddress>
#include <QTextStream>
#include <QRegularExpression>
#include <QDebug>
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

    // 设备列表
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            ui->deviceCombo->addItem(QString::fromUtf8(d->name));
        }
        pcap_freealldevs(alldevs);
    }
    ui->modeCombo->addItem("混杂模式");
    ui->modeCombo->addItem("直接模式");

    connect(ui->startBtn, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(ui->stopBtn, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(ui->packetTable, &QTableWidget::cellClicked, this, &MainWindow::onPacketTableClicked);
    connect(ui->macFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->ethTypeFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->ipFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->protoFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    connect(ui->portFilterEdit, &QLineEdit::editingFinished, this, &MainWindow::onFilterChanged);
    ui->stopBtn->setEnabled(false);

    // 设置表头自适应
    ui->packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

MainWindow::~MainWindow() {
    if (captureThread) {
        captureThread->stop();
        captureThread->wait();
        delete captureThread;
    }
    delete ui;
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
    QString dev = ui->deviceCombo->currentText();
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

// 解析以太网/IP/TCP/UDP/ICMP头部，填充PacketInfo
void MainWindow::parseAndDisplayPacket(const QByteArray &data, const struct pcap_pkthdr *header) {
    if (data.size() < 14) return; // 以太网头部
    PacketInfo info;
    info.rawData = data;
    info.time = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    // 以太网头
    const uchar *d = (const uchar*)data.constData();
    info.dstMac = QString("%1-%2-%3-%4-%5-%6").arg(d[0],2,16,QChar('0')).arg(d[1],2,16,QChar('0')).arg(d[2],2,16,QChar('0')).arg(d[3],2,16,QChar('0')).arg(d[4],2,16,QChar('0')).arg(d[5],2,16,QChar('0')).toUpper();
    info.srcMac = QString("%1-%2-%3-%4-%5-%6").arg(d[6],2,16,QChar('0')).arg(d[7],2,16,QChar('0')).arg(d[8],2,16,QChar('0')).arg(d[9],2,16,QChar('0')).arg(d[10],2,16,QChar('0')).arg(d[11],2,16,QChar('0')).toUpper();
    quint16 ethType = (d[12]<<8) | d[13];
    info.ethType = QString("0x%1").arg(ethType,4,16,QChar('0')).toUpper();
    int ipOffset = 14;
    if (ethType == 0x0800 && data.size() >= ipOffset+20) { // IPv4
        const uchar *ip = d+ipOffset;
        int ipHeaderLen = (ip[0]&0x0F)*4;
        info.srcIp = QString("%1.%2.%3.%4").arg(ip[12]).arg(ip[13]).arg(ip[14]).arg(ip[15]);
        info.dstIp = QString("%1.%2.%3.%4").arg(ip[16]).arg(ip[17]).arg(ip[18]).arg(ip[19]);
        quint8 proto = ip[9];
        switch(proto) {
        case 1: info.protocol = "ICMP"; break;
        case 6: info.protocol = "TCP"; break;
        case 17: info.protocol = "UDP"; break;
        default: info.protocol = QString::number(proto); break;
        }
        if (proto == 6 && data.size() >= ipOffset+ipHeaderLen+20) { // TCP
            const uchar *tcp = d+ipOffset+ipHeaderLen;
            info.srcPort = QString::number((tcp[0]<<8)|tcp[1]);
            info.dstPort = QString::number((tcp[2]<<8)|tcp[3]);
        } else if (proto == 17 && data.size() >= ipOffset+ipHeaderLen+8) { // UDP
            const uchar *udp = d+ipOffset+ipHeaderLen;
            info.srcPort = QString::number((udp[0]<<8)|udp[1]);
            info.dstPort = QString::number((udp[2]<<8)|udp[3]);
        }
    } else if (ethType == 0x0806 && data.size() >= ipOffset+28) { // ARP
        info.protocol = "ARP";
    } else {
        info.protocol = "Other";
    }
    if (!filterPacket(info)) return;
    int row = ui->packetTable->rowCount();
    ui->packetTable->insertRow(row);
    ui->packetTable->setItem(row, 0, new QTableWidgetItem(info.time));
    ui->packetTable->setItem(row, 1, new QTableWidgetItem(info.srcMac));
    ui->packetTable->setItem(row, 2, new QTableWidgetItem(info.dstMac));
    ui->packetTable->setItem(row, 3, new QTableWidgetItem(info.ethType));
    ui->packetTable->setItem(row, 4, new QTableWidgetItem(info.srcIp));
    ui->packetTable->setItem(row, 5, new QTableWidgetItem(info.dstIp));
    ui->packetTable->setItem(row, 6, new QTableWidgetItem(info.protocol));
    ui->packetTable->setItem(row, 7, new QTableWidgetItem(QString::number(data.size())));
    packetList.append(info);
}

void MainWindow::onPacketTableClicked(int row, int /*column*/) {
    if (row < 0 || row >= packetList.size()) return;
    const PacketInfo &info = packetList[row];
    updateProtocolTree(info);
    updateRawDataView(info.rawData);
}

void MainWindow::updateProtocolTree(const PacketInfo &info) {
    ui->protocolTree->clear();
    QTreeWidgetItem *eth = new QTreeWidgetItem(ui->protocolTree, QStringList() << "以太网头部");
    eth->addChild(new QTreeWidgetItem(QStringList() << ("源MAC: " + info.srcMac)));
    eth->addChild(new QTreeWidgetItem(QStringList() << ("目的MAC: " + info.dstMac)));
    eth->addChild(new QTreeWidgetItem(QStringList() << ("类型: " + info.ethType)));
    if (!info.srcIp.isEmpty()) {
        QTreeWidgetItem *ip = new QTreeWidgetItem(eth, QStringList() << "IP头部");
        ip->addChild(new QTreeWidgetItem(QStringList() << ("源IP: " + info.srcIp)));
        ip->addChild(new QTreeWidgetItem(QStringList() << ("目的IP: " + info.dstIp)));
        ip->addChild(new QTreeWidgetItem(QStringList() << ("协议: " + info.protocol)));
        if (!info.srcPort.isEmpty()) {
            QTreeWidgetItem *trans = new QTreeWidgetItem(ip, QStringList() << (info.protocol + "头部"));
            trans->addChild(new QTreeWidgetItem(QStringList() << ("源端口: " + info.srcPort)));
            trans->addChild(new QTreeWidgetItem(QStringList() << ("目的端口: " + info.dstPort)));
        }
    }
    ui->protocolTree->expandAll();
}

void MainWindow::updateRawDataView(const QByteArray &data, int, int) {
    // Wireshark风格：左侧16进制，右侧ASCII
    QString hex, ascii;
    for (int i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) {
            if (i > 0) hex += "  " + ascii + "\n", ascii.clear();
            hex += QString("%1 ").arg(i, 4, 16, QChar('0'));
        }
        hex += QString("%1 ").arg((quint8)data[i], 2, 16, QChar('0'));
        char c = data[i];
        ascii += (c >= 32 && c <= 126) ? c : '.';
    }
    if (!ascii.isEmpty()) hex += QString("  %1").arg(ascii);
    ui->rawDataEdit->setPlainText(hex);
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
    if (!protoFilter.isEmpty() && info.protocol.toUpper() != protoFilter) return false;
    // 端口过滤
    QString portFilter = ui->portFilterEdit->text().trimmed();
    if (!portFilter.isEmpty() && info.srcPort != portFilter && info.dstPort != portFilter) return false;
    return true;
}

void MainWindow::onFilterChanged() {
    ui->packetTable->setRowCount(0);
    for (const PacketInfo &info : packetList) {
        if (filterPacket(info)) {
            int row = ui->packetTable->rowCount();
            ui->packetTable->insertRow(row);
            ui->packetTable->setItem(row, 0, new QTableWidgetItem(info.time));
            ui->packetTable->setItem(row, 1, new QTableWidgetItem(info.srcMac));
            ui->packetTable->setItem(row, 2, new QTableWidgetItem(info.dstMac));
            ui->packetTable->setItem(row, 3, new QTableWidgetItem(info.ethType));
            ui->packetTable->setItem(row, 4, new QTableWidgetItem(info.srcIp));
            ui->packetTable->setItem(row, 5, new QTableWidgetItem(info.dstIp));
            ui->packetTable->setItem(row, 6, new QTableWidgetItem(info.protocol));
            ui->packetTable->setItem(row, 7, new QTableWidgetItem(QString::number(info.rawData.size())));
        }
    }
}
