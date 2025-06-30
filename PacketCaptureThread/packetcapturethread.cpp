#include "packetcapturethread.h"
#include <QMutexLocker>

PacketCaptureThread::PacketCaptureThread(QObject *parent)
    : QThread(parent) {
}

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
