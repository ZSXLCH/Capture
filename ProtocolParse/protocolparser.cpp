#include "protocolparser.h"
#include <QStringList>
#include <QTreeWidgetItem>

// 将MAC地址转换为字符串格式
QString ProtocolParser::macToString(const uchar *mac) {
    return QString("%1-%2-%3-%4-%5-%6")
    .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0')).toUpper();
}

// 将IPv4地址转换为字符串格式
QString ProtocolParser::ipToString(const uchar *ip) {
    return QString("%1.%2.%3.%4").arg(ip[0]).arg(ip[1]).arg(ip[2]).arg(ip[3]);
}

// 将IPv6地址转换为字符串格式
QString ProtocolParser::ipv6ToString(const uchar *ipv6) {
    QString result;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) result += ":";
        result += QString("%1").arg((ipv6[i] << 8) | ipv6[i + 1], 4, 16, QChar('0'));
    }
    return result;
}

// 主解析函数
bool ProtocolParser::parsePacket(const QByteArray &data, PacketInfo &info) {
    int offset = parseEthernet(data, info, nullptr);
    return offset >= 0;
}

// 解析以太网帧头部
int ProtocolParser::parseEthernet(const QByteArray &data, PacketInfo &info, ProtocolTreeItem *parent) {
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
int ProtocolParser::parseArp(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
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
int ProtocolParser::parseIpV4(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
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
int ProtocolParser::parseIpV6(const QByteArray &data, int offset, PacketInfo &info, ProtocolTreeItem *parent) {
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
int ProtocolParser::parseIcmp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent) {
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
int ProtocolParser::parseTcp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent) {
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
int ProtocolParser::parseUdp(const QByteArray &data, int offset, int len, PacketInfo &info, ProtocolTreeItem *parent) {
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
void ProtocolParser::parseApplicationLayer(const QByteArray &data, int offset, int len, quint16 srcPort, quint16 dstPort, PacketInfo &info, ProtocolTreeItem *parent) {
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
void ProtocolParser::parseHTTP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
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
void ProtocolParser::parseDNS(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
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
QString ProtocolParser::parseDnsName(const QByteArray &data, int &offset, int baseOffset) {
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
void ProtocolParser::parseDHCP(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
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
void ProtocolParser::parseDhcpOptions(const QByteArray &data, int offset, int len, ProtocolTreeItem *parent) {
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
