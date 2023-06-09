/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TIMELINE_DELEGATE_H
#define TIMELINE_DELEGATE_H

/*
 * @file Timeline delegate.
 *
 * QStyledItemDelegate subclass that will draw a timeline indicator for
 * the specified value.
 *
 * This is intended to be used in QTreeWidgets to show timelines, e.g. for
 * conversations.
 * To use it, first call setItemDelegate:
 *
 *   myTreeWidget()->setItemDelegateForColumn(col_time_start_, new TimelineDelegate());
 *
 * Then, for each QTreeWidgetItem, set or return a timeline_span for the start and end
 * of the timeline in pixels relative to the column width.
 *
 *   setData(col_start_, Qt::UserRole, start_span);
 *   setData(col_end_, Qt::UserRole, end_span);
 *
 */

#include <QStyledItemDelegate>

// Pixels are relative to item rect and will be clipped.
struct timeline_span {
    int start;
    int width;

    double startTime;
    double stopTime;
    double minRelTime;
    double maxRelTime;

    int colStart;
    int colDuration;
};

Q_DECLARE_METATYPE(timeline_span)

class TimelineDelegate : public QStyledItemDelegate
{
public:
    TimelineDelegate(QWidget *parent = 0);

    void setDataRole(int role);

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
private:

    int _dataRole;
};

#endif // TIMELINE_DELEGATE_H
