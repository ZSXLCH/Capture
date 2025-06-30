#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include <QByteArray>
#include <QMap>

// 协议层定义
enum ProtocolLayer {
    LAYER_ETHERNET = 0,
    LAYER_IP,
    LAYER_TRANSPORT,
    LAYER_APPLICATION
};

// 协议字段信息
struct ProtocolField {
    int offset;     // 在数据包中的偏移
    int length;     // 字段长度
    ProtocolLayer layer;  // 所属层
};

// 数据包结构体
struct PacketInfo {
    QByteArray rawData;
    QString time;
    QString srcMac;
    QString dstMac;
    QString ethType;
    QString srcIp;
    QString dstIp;
    QString protocol;
    QString srcPort;
    QString dstPort;
    QString appProtocol;  // 应用层协议
    QString info;         // 信息列，显示数据包详细信息
    int originalIndex;    // 原始索引，用于过滤后保持序号
    QMap<QString, ProtocolField> fields; // 协议字段映射，用于高亮
};

#endif // COMMON_H
