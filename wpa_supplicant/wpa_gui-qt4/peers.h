/*
 * wpa_gui - Peers class
 * Copyright (c) 2009, Atheros Communications
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef PEERS_H
#define PEERS_H

#include <QObject>
#include <QStandardItemModel>
#include "wpamsg.h"
#include "ui_peers.h"

class WpaGui;

class Peers : public QDialog, public Ui::Peers
{
	Q_OBJECT

public:
	Peers(QWidget *parent = 0, const char *name = 0,
		    bool modal = false, Qt::WFlags fl = 0);
	~Peers();
	void setWpaGui(WpaGui *_wpagui);
	void event_notify(WpaMsg msg);

public slots:
	virtual void context_menu(const QPoint &pos);
	virtual void enter_pin();
	virtual void ctx_refresh();

protected slots:
	virtual void languageChange();

private:
	void add_station(QString info);
	void add_stations();
	void add_single_station(const char *addr);
	void add_scan_results();
	void update_peers();
	QStandardItem * find_addr(QString addr);

	WpaGui *wpagui;
	QStandardItemModel model;
	QIcon *default_icon;
	QStandardItem *ctx_item;
};

#endif /* PEERS_H */