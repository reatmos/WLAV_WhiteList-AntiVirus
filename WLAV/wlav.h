#pragma once

#include <QtWidgets/QMainWindow>
#include <QFileDialog>
#include <QDebug>
#include <QDesktopServices>
#include <QUrl>
#include <QtSql/QSql>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlquery>
#include "ui_wlav.h"

class WLAV : public QMainWindow
{
	Q_OBJECT

public:
	WLAV(QWidget* parent = Q_NULLPTR);

private:
	Ui::WLAVClass ui;

public slots:
	void ButtonClicked();
	void SelectPath();
	void openDir();
	void openUrl();
};