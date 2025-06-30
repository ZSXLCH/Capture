#include "protocoltreeitem.h"

ProtocolTreeItem::ProtocolTreeItem(const QStringList &strings)
    : QTreeWidgetItem(strings) {
}

void ProtocolTreeItem::setFieldInfo(int offset, int length, ProtocolLayer layer) {
    fieldOffset = offset;
    fieldLength = length;
    fieldLayer = layer;
}
