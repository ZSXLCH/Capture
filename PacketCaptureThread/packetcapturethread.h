#ifndef PACKETCAPTURETHREAD_H
#define PACKETCAPTURETHREAD_H

#include <QThread>
#include <QMutex>
#include <QString>
#include <QByteArray>

extern "C" {
#include <pcap.h>
}

class PacketCaptureThread : public QThread {
    Q_OBJECT

public:
    explicit PacketCaptureThread(QObject *parent = nullptr);
    ~PacketCaptureThread() override = default;

    void setDevice(const QString &devName, bool promisc);
    void setFilter(const QString &filterExp);
    void stop();

signals:
    void packetCaptured(const QByteArray &data, const struct pcap_pkthdr *header);

protected:
    void run() override;

private:
    QString deviceName;
    bool promiscMode = true;
    QString filterExp;
    volatile bool running = true;
    pcap_t *adhandle = nullptr;
    QMutex mutex;
};

#endif // PACKETCAPTURETHREAD_H
