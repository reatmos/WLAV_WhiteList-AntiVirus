"""
Script to check SHA256 with Virustotal API
Made by Reamos
Github : reatmos
Twitter : @Pa1ath
Blog : https://re-atmosphere.tistory.com/
"""

import urllib
import urllib.request
import urllib.parse
import json
import time
import sqlite3
import os
import datetime


# API key for Test and EasterEgg(Public API)
tempkey = 'e590033d4e5c6d186201e8c5435c0b26e7a6abd8cbcdc17c5fb026e8db06e088'
host = 'www.virustotal.com'
rurl = 'https://www.virustotal.com/vtapi/v2/file/report'
sha256str = ''

# Set locate for API Key file 
keyfile = open('C:\\WLAV\\Temp\\vtkey.txt', 'r')
line=keyfile.readline()
vtkey = line.strip('\n')
fields = [('apikey', vtkey)]

# Files Count
txtf = open('C:\\WLAV\\Temp\\Hash.txt', 'r')
cnt = len(txtf.readlines())
fint = 1

# Set locate for SHA256 list
txtf = open('C:\\WLAV\\Temp\\Hash.txt', 'r')

nowDate = datetime.datetime.now()
# Create log file
log = open('C:\\WLAV\\Log\\WLAV_' + nowDate.strftime('%Y%m%d_%H%M%S') + '.txt', 'w', encoding='UTF-8')

print("")

while True:
    # Load Virustotal API
    line=txtf.readline()
    sha256str = line.strip('\n')
    if not sha256str: break
    parameters = {'resource': sha256str, 'apikey': vtkey}
    data = urllib.parse.urlencode(parameters).encode('utf-8')
    req = urllib.request.Request(rurl, data)
    response = urllib.request.urlopen(req)
    data = response.read()
    data = json.loads(data.decode('utf-8'))
    sha256 = data.get('sha256', {})
    scan = data.get('scans', {})
    keys = scan.keys()
    # Connect to WhiteList Database
    conn = sqlite3.connect(r'C:\\WLAV\\WhiteList.db')
    cur = conn.cursor()
    # Connect to Blacklist Database
    vcon = sqlite3.connect(r'C:\\WLAV\\BlackList.db')
    vcur = vcon.cursor()
    print('========== Virus Total Loading ==========')
    print('=========================================\n')
    #Files Order Output
    print('%d of %d' % (fint, cnt))
    # Write file path on log file
    cur.execute("SELECT File_Name FROM HASH WHERE Hash_Value='%s'" % sha256str)
    ftu = cur.fetchone()
    fn = ''.join(ftu)
    print('\nFile : %s\n' % fn)
    tlog = 'File(%d/%d) : %s\n\n' % (fint, cnt, fn)
    log.write(tlog)
    log.write('=========================================\n')
    fint += 1
    for i in range(100):
        print('Scanning.. %d%%' % i, end='\r', flush=True)
        time.sleep(0.2)
    # If it can't check file
    if sha256 == {}:
        print("I can't scan this file.\n")
        log.write("I can't scan this file.\n")
        # Connect to Nonelist
        con = sqlite3.connect(r'C:\\WLAV\\NoneList.db')
        curr = con.cursor()
        # Move Whitelist data to Nonelist and Delete Whitelist data
        cur.execute("SELECT File_Name FROM HASH WHERE Hash_Value='%s'" % sha256str)
        ftu = cur.fetchone()
        fn = ''.join(ftu)
        curr.execute("CREATE TABLE IF NOT EXISTS HASH(ID INTEGER PRIMARY KEY AUTOINCREMENT, File_Name VARCHAR(255), Hash_Value VARCHAR(255))")
        curr.execute("INSERT INTO HASH(File_Name, Hash_Value) VALUES('%s', '%s')" % (fn, sha256str))
        con.commit()
        cur.execute("DELETE FROM HASH WHERE Hash_Value='%s'" % sha256str)
        conn.commit()
    else:
        vtmp=0;
        for key in keys:
            # If it has result by AhnLab-V3
            if key == 'AhnLab-V3':
                tlog = '%-20s : %s\n' % (key, scan[key]['result'])
                log.write(tlog)
                # If it find virus
                if scan[key]['result'] != None:
                    # Move Whitelist data to Blacklist and Delete Whitelist data
                    cur.execute("SELECT File_Name FROM HASH WHERE Hash_Value='%s'" % sha256)
                    ftu = cur.fetchone()
                    fn = ''.join(ftu)
                    vcur.execute("CREATE TABLE IF NOT EXISTS HASH(ID INTEGER PRIMARY KEY AUTOINCREMENT, File_Name VARCHAR(255), Hash_Value VARCHAR(255))")
                    vcur.execute("INSERT INTO HASH(File_Name, Hash_Value) VALUES('%s', '%s')" % (fn, sha256str))
                    vcon.commit()
                    # Change file's filename extension to .bla
                    nname = os.path.splitext(fn)[0] + '.bla'
                    os.rename(fn, nname)
                    cur.execute("DELETE FROM HASH WHERE Hash_Value='%s'" % sha256)
                    conn.commit()
                    vtmp=1;
                    break
            # If it has result by ALYac
            elif key == 'ALYac':
                tlog = '%-20s : %s\n' % (key, scan[key]['result'])
                log.write(tlog)
                if scan[key]['result'] != None:
                    cur.execute("SELECT File_Name FROM HASH WHERE Hash_Value='%s'" % sha256)
                    ftu = cur.fetchone()
                    fn = ''.join(ftu)
                    vcur.execute("CREATE TABLE IF NOT EXISTS HASH(ID INTEGER PRIMARY KEY AUTOINCREMENT, File_Name VARCHAR(255), Hash_Value VARCHAR(255))")
                    vcur.execute("INSERT INTO HASH(File_Name, Hash_Value) VALUES('%s', '%s')" % (fn, sha256str))
                    vcon.commit()
                    nname = os.path.splitext(fn)[0] + '.bla'
                    os.rename(fn, nname)
                    cur.execute("DELETE FROM HASH WHERE Hash_Value='%s'" % sha256)
                    conn.commit()
                    vtmp=1;
                    break
            # If it has result by nProtect
            elif key == 'nProtect':
                tlog = '%-20s : %s\n' % (key, scan[key]['result'])
                log.write(tlog)
                if scan[key]['result'] != None:
                    cur.execute("SELECT File_Name FROM HASH WHERE Hash_Value='%s'" % sha256)
                    ftu = cur.fetchone()
                    fn = ''.join(ftu)
                    vcur.execute("CREATE TABLE IF NOT EXISTS HASH(ID INTEGER PRIMARY KEY AUTOINCREMENT, File_Name VARCHAR(255), Hash_Value VARCHAR(255))")
                    vcur.execute("INSERT INTO HASH(File_Name, Hash_Value) VALUES('%s', '%s')" % (fn, sha256str))
                    vcon.commit()
                    nname = os.path.splitext(fn)[0] + '.bla'
                    os.rename(fn, nname)
                    cur.execute("DELETE FROM HASH WHERE Hash_Value='%s'" % sha256)
                    conn.commit()
                    vtmp=1;
                    break
            # If it has result by ViRobot
            elif key == 'ViRobot':
                tlog = '%-20s : %s\n' % (key, scan[key]['result'])
                log.write(tlog)
                if scan[key]['result'] != None:
                    cur.execute("SELECT File_Name FROM HASH WHERE Hash_Value='%s'" % sha256)
                    ftu = cur.fetchone()
                    fn = ''.join(ftu)
                    vcur.execute("CREATE TABLE IF NOT EXISTS HASH(ID INTEGER PRIMARY KEY AUTOINCREMENT, File_Name VARCHAR(255), Hash_Value VARCHAR(255))")
                    vcur.execute("INSERT INTO HASH(File_Name, Hash_Value) VALUES('%s', '%s')" % (fn, sha256str))
                    vcon.commit()
                    nname = os.path.splitext(fn)[0] + '.bla'
                    os.rename(fn, nname)
                    cur.execute("DELETE FROM HASH WHERE Hash_Value='%s'" % sha256)
                    conn.commit()
                    vtmp=1;
                    break
        # If there is virus in files
        if vtmp==1:
            print('I found virus on this file.\n')
            tlog = "\nThe virus was detected in '%s'\nso I moved to the blacklist\nand I changed the file extension to bla.\n" % fn
            log.write(tlog)
        else:
            print("I confirmed this file is safe.\n") 

    log.write('=========================================\n\n')

txtf.close()
log.write('================= clear =================') 
log.close()
time.sleep(1)