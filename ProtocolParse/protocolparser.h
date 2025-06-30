#ifndef PROTOCOLPARSER_H
#define PROTOCOLPARSER_H

#include <QByteArray>
#include <QString>
#include "../PacketInfo/packetinfo.h"
#include "../ProtocolTreeItem/protocoltreeitem.h"

class ProtocolParser {
public:
    ProtocolParser() = default;
    ~ProtocolParser() = default;

    // 主解析函数
    bool parsePacket(const QByteArray &data, PacketInfo &info);

    // 各层协议解析函数
    int parseEthernet(const QByteArray &data, PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    int parseArp(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    int parseIpV4(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    int parseIpV6(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    int parseIcmp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    int parseTcp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    int parseUdp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent = nullptr);

    // 应用层协议解析
    void parseApplicationLayer(const QByteArray &data, int offset, int len, quint16 srcPort, quint16 dstPort,
                               PacketInfo &info, ProtocolTreeItem *parent = nullptr);
    void parseHTTP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);
    void parseDNS(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);
    void parseDHCP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);
    void parseDhcpOptions(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent);

    // 工具函数
    static QString ipToString(const uchar *ip);
    static QString ipv6ToString(const uchar *ipv6);
    static QString macToString(const uchar *mac);
    static QString parseDnsName(const QByteArray &data, int &offset, int baseOffset);
};

#endif // PROTOCOLPARSER_H
