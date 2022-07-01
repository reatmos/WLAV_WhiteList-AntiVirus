/*
* File Check Program base on Whitelist
* Made by Reatmos
* Github : reatmos
* Tiwtter : @Pa1ath
* Blog : https://re-atmosphere.tistory.com/
*/

#include "wlav.h"
#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <fstream>
#include <direct.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <QString.h>

// Crash prevention on QT and Python
#pragma push_macro("slots")
#undef slots
#include "Python.h"
#pragma pop_macro("slots")

using namespace std;

#ifdef _UNICODE
#define tcout wcout
#define tcerr wcerr
#else
#define tcout cout
#define tcerr cerr
#endif

const char* mdir = "C:\\WLAV";
const char* tdir = "C:\\WLAV\\Temp";
const char* ldir = "C:\\WLAV\\Log";
char wtemp[] = "C:\\WLAV\\\\Temp\\White.txt";
char ntemp[] = "C:\\WLAV\\\\Temp\\None.txt";
char btemp[] = "C:\\WLAV\\\\Temp\\Black.txt";
char vtkey[] = "C:\\WLAV\\Temp\\vtkey.txt";
const char* wdb = "C:\\WLAV\\WhiteList.db";
TCHAR filename[MAX_PATH];
char calc_hash[65];
const char* first;
const char* second;
const char* vtapi;
const char* logmes;
int exsit = 0;
QString path;
QString szPath;

int callback(void* NotUsed, int argc, char** argv, char** azColName)
{
	NotUsed = 0;

	for (int i = 0; i < argc; i++)
	{
		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}

	printf("\n");

	return 0;
}

int createDB(const char* s)
{
	sqlite3* DB;
	int exit = 0;

	exit = sqlite3_open(s, &DB);

	sqlite3_close(DB);

	return 0;
}

int createfTable(const char* s)
{
	sqlite3* DB;

	const char* sql = "CREATE TABLE IF NOT EXISTS HASH("
		"ID INTEGER PRIMARY KEY AUTOINCREMENT,"
		"File_Name				VARCHAR(255),"
		"Hash_Value            VARCHAR(255) );";
	try
	{
		int exit = 0;
		exit = sqlite3_open(s, &DB);

		char* messaggeError;
		exit = sqlite3_exec(DB, sql, callback, 0, &messaggeError);

		if (exit != SQLITE_OK) {
			sqlite3_free(messaggeError);
		}
		sqlite3_close(DB);
	}
	catch (const exception& e) {
		cerr << e.what();
	}

	return 0;
}

void InsertData()
{
	QString sql = "QSQLITE";
	QString dbName = "WhiteList";
	QSqlDatabase WhiteList = QSqlDatabase::addDatabase(sql, dbName);
	WhiteList.setDatabaseName("C:\\WLAV\\WhiteList.db");
	if (!WhiteList.open())
	{
		QSqlDatabase::removeDatabase("WhiteList");
	}
	QSqlQuery query(WhiteList);
	query.prepare("INSERT INTO HASH(File_Name, Hash_Value) VALUES(?, ?);");
	query.addBindValue(szPath);
	query.addBindValue(QString(calc_hash));
	query.exec();
}

// Calculate and Output SHA256 of files
int Calc_SHA256(WCHAR* tpath, char* toutput)
{
	FILE* file = _wfopen(tpath, L"rb");
	if (!file)return -1;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	const int bufSize = 32768;
	unsigned char* buffer = (unsigned char*)malloc(bufSize);
	SHA256_CTX sha256;
	int bytesRead = 0;

	if (!buffer)return -2;

	SHA256_Init(&sha256);

	while ((bytesRead = fread(buffer, 1, bufSize, file))) {
		SHA256_Update(&sha256, buffer, bytesRead);
	}

	SHA256_Final(hash, &sha256);
	int i = 0;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(toutput + (i * 2), "%02x", hash[i]);
	}
	toutput = 0;
	fclose(file);

	return 0;
}

// Load WhiteList Data
void PyCallWDB()
{
	PyObject* pName, * pModule, * pFunc, * pValue;

	Py_Initialize();
	PyRun_SimpleString("import os, sys");
	PyRun_SimpleString("sys.path.append(os.getcwd() + '\\Scripts')");
	pName = PyUnicode_FromString("OutputWDB");
	pModule = PyImport_Import(pName);
	pFunc = PyObject_GetAttrString(pModule, "OutDB");
	pValue = PyObject_CallObject(pFunc, NULL);
	Py_Finalize();
}

// Load NoneList Data
void PyCallNDB()
{
	PyObject* pName, * pModule, * pFunc, * pValue;

	Py_Initialize();
	PyRun_SimpleString("import os, sys");
	PyRun_SimpleString("sys.path.append(os.getcwd() + '\\Scripts')");
	pName = PyUnicode_FromString("OutputNDB");
	pModule = PyImport_Import(pName);
	pFunc = PyObject_GetAttrString(pModule, "OutDB");
	pValue = PyObject_CallObject(pFunc, NULL);
	Py_Finalize();
}

// Load BlackList Data
void PyCallBDB()
{
	PyObject* pName, * pModule, * pFunc, * pValue;

	Py_Initialize();
	PyRun_SimpleString("import os, sys");
	PyRun_SimpleString("sys.path.append(os.getcwd() + '\\Scripts')");
	pName = PyUnicode_FromString("OutputBDB");
	pModule = PyImport_Import(pName);
	pFunc = PyObject_GetAttrString(pModule, "OutDB");
	pValue = PyObject_CallObject(pFunc, NULL);
	Py_Finalize();
}

// SHA256 Check Script
void PyCheckHash()
{
	PyObject* pName, * pModule, * pFunc, * pValue;

	Py_Initialize();
	PyRun_SimpleString("import os, sys");
	PyRun_SimpleString("sys.path.append(os.getcwd() + '\\Scripts')");
	pName = PyUnicode_FromString("pyexe");
	pModule = PyImport_Import(pName);
	pFunc = PyObject_GetAttrString(pModule, "pyexe");
	pValue = PyObject_CallObject(pFunc, NULL);
	Py_Finalize();
}

WLAV::WLAV(QWidget* parent)
	: QMainWindow(parent)
{
	// Create folder for WLAV program
	_mkdir(mdir);
	_mkdir(tdir);
	_mkdir(ldir);

	sqlite3* DB;

	// If temp file is exist, delete file
	if (_access(wtemp, 0) != -1)
		int result = remove(wtemp);

	if (_access(ntemp, 0) != -1)
		int result = remove(ntemp);

	if (_access(btemp, 0) != -1)
		int result = remove(btemp);

	if (_access(vtkey, 0) != -1)
		int result = remove(vtkey);

	ui.setupUi(this);

	connect(ui.pushButton, SIGNAL(clicked()), this, SLOT(ButtonClicked()));
	connect(ui.pushButton_4, SIGNAL(clicked()), this, SLOT(SelectPath()));
	connect(ui.pushButton_3, SIGNAL(clicked()), this, SLOT(openDir()));
	connect(ui.pushButton_2, SIGNAL(clicked()), this, SLOT(openUrl()));
}

void WLAV::SelectPath()
{
	path = QFileDialog::getExistingDirectory(this, "Select Directory", QDir::homePath(), QFileDialog::ShowDirsOnly);
	ui.label_3->setText(path);
}

void WLAV::ButtonClicked()
{
	QDir dir = path;
	QString key = ui.lineEdit->text();
	int length = key.length();
	ofstream fout;
	BOOL subDirTraverse = FALSE;
	char count[MAX_PATH];
	int n = 0;
	int find = 0;

	// If folder isn't exist, create folder
	if (_access(mdir, 0) == -1)
		_mkdir(mdir);

	if (_access(tdir, 0) == -1)
		_mkdir(tdir);

	if (_access(ldir, 0) == -1)
		_mkdir(ldir);

	char hash[] = "C:\\WLAV\\Temp\\Hash.txt";
	if (_access(hash, 0) != -1)
		int result = remove(hash);

	// Check API key
	if (length == 64)
	{
		fout.open("C:\\WLAV\\Temp\\vtkey.txt", std::ios_base::out | std::ios_base::app);
		fout << key.toStdString().c_str() << endl;
		fout.close();
		
		createDB(wdb);
		createfTable(wdb);

		if (ui.radioButton_4->isChecked())
		{
			// Run twice to receive the results of the scan immediately
			for (int t = 0; t < 2; t++)
			{
				PyCallWDB();
				PyCallNDB();
				PyCallBDB();
				ui.plainTextEdit->setPlainText(QString::fromLocal8Bit("[File]\n"));
				*count = 0;

				// Include Subdirectory
				QDirIterator iterator(dir.absolutePath(), QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
				while (iterator.hasNext()) {
					QFile file(iterator.next());
					Calc_SHA256((WCHAR*)file.fileName().toStdWString().c_str(), calc_hash);
					ui.plainTextEdit->appendPlainText(file.fileName());

					char line[MAX_PATH];
					ifstream fin("C:\\WLAV\\Temp\\White.txt");
					ifstream nfin("C:\\WLAV\\Temp\\None.txt");
					ifstream vfin("C:\\WLAV\\Temp\\Black.txt");
					std::ofstream fout;
					find = 0;

					// Check there is files in Whitelist
					if (fin.is_open())
					{
						while (fin.getline(line, sizeof(line)))
						{
							char* ptr = strstr(line, calc_hash);

							if (ptr != NULL)
							{
								find = 1;
								break;
							}
						}
					}

					// Check there is files in Nonelist
					if (nfin.is_open())
					{
						while (nfin.getline(line, sizeof(line)))
						{
							char* ptr = strstr(line, calc_hash);

							if (ptr != NULL)
							{
								find = 2;
								break;
							}
						}
					}

					// Check there is files in Blacklist
					if (vfin.is_open())
					{
						while (vfin.getline(line, sizeof(line)))
						{
							char* ptr = strstr(line, calc_hash);

							if (ptr != NULL)
							{
								find = 3;
								break;
							}
						}
					}

					if (find == 1)
					{
						// If file is exist in Whitelist
						ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("It's safe.\n"));
						count[n] = 0;
					}
					else if (find == 2)
					{
						// If file is exist in Nonelist
						ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("I can't check it.\n"));
						count[n] = 0;
					}
					else if (find == 3)
					{
						// If file is exist in Blacklist
						ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("It's dangerous.\n"));
						count[n] = 0;
					}
					else if (find == 0)
					{
						// If file is new file
						fout.open("C:\\WLAV\\Temp\\Hash.txt", std::ios_base::out | std::ios_base::app);
						// Output SHA256 to file
						fout << calc_hash << endl;
						szPath = file.fileName();
						InsertData();
						count[n] = 1;
					}
					fout.close();
					fin.close();
					n++;
				}
				// Scan only on the first run
				if (t == 0)
				{
					// Check for new files in the file list
					int yes = 0;
					for (int y = 0; y < n; y++)
					{
						if (count[y] == 1)
						{
							// New file is 1 in file list
							yes = 1;
							break;
						}
					}
					// If there is a new file in the file list
					if (yes == 1)
					{
						// Run SHA256 Check Script
						PyCheckHash();
					}
				}
			}
		}
		else if (ui.radioButton_3->isChecked())
		{
			for (int z = 0; z < 2; z++)
			{
				PyCallWDB();
				PyCallNDB();
				PyCallBDB();
				ui.plainTextEdit->setPlainText(QString::fromLocal8Bit("[File]\n"));
				*count = 0;

				// Exclude Subdirectory
				foreach(QFileInfo item, dir.entryInfoList(QDir::NoDotAndDotDot | QDir::Files))
				{
					Calc_SHA256((WCHAR*)item.absoluteFilePath().toStdWString().c_str(), calc_hash);
					ui.plainTextEdit->appendPlainText(item.absoluteFilePath());

					char line[MAX_PATH];
					ifstream fin("C:\\WLAV\\Temp\\White.txt");
					ifstream nfin("C:\\WLAV\\Temp\\None.txt");
					ifstream vfin("C:\\WLAV\\Temp\\Black.txt");
					std::ofstream fout;
					find = 0;

					if (fin.is_open())
					{
						while (fin.getline(line, sizeof(line)))
						{
							char* ptr = strstr(line, calc_hash);

							if (ptr != NULL)
							{
								find = 1;
								break;
							}
						}
					}

					if (nfin.is_open())
					{
						while (nfin.getline(line, sizeof(line)))
						{
							char* ptr = strstr(line, calc_hash);

							if (ptr != NULL)
							{
								find = 2;
								break;
							}
						}
					}

					if (vfin.is_open())
					{
						while (vfin.getline(line, sizeof(line)))
						{
							char* ptr = strstr(line, calc_hash);

							if (ptr != NULL)
							{
								find = 3;
								break;
							}
						}
					}

					if (find == 1)
					{
						ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("It's safe.\n"));
						count[n] = 0;
					}
					else if (find == 2)
					{
						ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("I can't check it.\n"));
						count[n] = 0;
					}
					else if (find == 3)
					{
						ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("It's dangerous.\n"));
						count[n] = 0;
					}
					else if (find == 0)
					{
						fout.open("C:\\WLAV\\Temp\\Hash.txt", std::ios_base::out | std::ios_base::app);
						fout << calc_hash << endl;
						szPath = item.absoluteFilePath();
						InsertData();
						count[n] = 1;
					}
					fout.close();
					fin.close();
					n++;
				}
				if (z == 0)
				{
					int yes = 0;
					for (int y = 0; y < n; y++)
					{
						if (count[y] == 1)
						{
							yes = 1;
							break;
						}
					}
					if (yes == 1)
					{
						PyCheckHash();
					}
				}
			}
		}

		ui.plainTextEdit->appendPlainText("----------");
		ui.plainTextEdit->appendPlainText(QString::fromLocal8Bit("\nFinish."));
	}
	else
		// If API key is wrong
		ui.plainTextEdit->setPlainText(QString::fromLocal8Bit("API key is wrong."));

	// Delte temp files
	if (_access(wtemp, 0) != -1)
		int result = remove(wtemp);
	
	if (_access(ntemp, 0) != -1)
		int result = remove(ntemp);

	if (_access(btemp, 0) != -1)
		int result = remove(btemp);
		
	if (_access(vtkey, 0) != -1)
		int result = remove(vtkey);

	if (_access(hash, 0) != -1)
		int result = remove(hash);
}

void WLAV::openDir()
{
	// Open WLAV directory
	QProcess::startDetached("C:\\Windows\\explorer.exe", QStringList() << "C:\\WLAV");
}

void WLAV::openUrl()
{
	// Open Virustotal Homepage by Browser
	QDesktopServices::openUrl(QUrl(QLatin1String("https://www.virustotal.com/gui/home/upload")));
}