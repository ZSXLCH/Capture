#ifndef PROTOCOLTREEITEM_H
#define PROTOCOLTREEITEM_H
#include <QTreeWidgetItem>
#include "../PacketInfo/packetinfo.h"

// 扩展的QTreeWidgetItem，存储协议字段信息以便高亮
class ProtocolTreeItem : public QTreeWidgetItem {
public:
    explicit ProtocolTreeItem(const QStringList &strings);

    void setFieldInfo(int offset, int length, ProtocolLayer layer);
    int getFieldOffset() const { return fieldOffset; }
    int getFieldLength() const { return fieldLength; }
    ProtocolLayer getFieldLayer() const { return fieldLayer; }

private:
    int fieldOffset = -1;
    int fieldLength = 0;
    ProtocolLayer fieldLayer = LAYER_ETHERNET;
};

#endif // PROTOCOLTREEITEM_H
