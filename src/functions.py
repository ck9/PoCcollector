import os, re, json
import sqlite3, requests
from dotenv import load_dotenv
from datetime import datetime
from nvd.main import getCVEinfo

thisPath = os.path.dirname(__file__)
load_dotenv(os.path.join(thisPath, '../.env'))

def getSignFromPoC(codePath):
  pathList = []
  if not os.path.isfile(codePath):
    return pathList
  with open(codePath, 'r') as f:
    code = f.read()
    pattern = r'[\'"](\{.+?\})*((\/[\w:%#\$&\?\(\)~\.=\+\-]+){2,})(\{.+?\})*[\'"]'
    for line in code.splitlines():
      match = re.search(pattern, line)
      if match:
        pathList.append(match.group(2))
    if not pathList:
      pattern = r'^([A-Z]+)\s((\/[\w:%#\$&\?\(\)~\.=\+\-]+)+)\sHTTP'
      for line in code.splitlines():
        match = re.search(pattern, line)
        if match:
          pathList.append(match.group(2))
  return list(set(pathList))
  # TODO ruby normalize_uriに対応
  # file:///Users/ck9/PoCcollector/test/data/High/02_collectPoC/CVE-2021-20837_50464.rb

def connectPoCDB():
  if not os.path.isfile(os.path.join(thisPath, '../PoC.db')):
    createPoCDB()
  conn = sqlite3.connect(os.path.join(thisPath, '../PoC.db'))
  return conn

def closePoCDB(db_conn):
  db_conn.close()

def getPoCurlList(db_conn):
  urlList = []
  c = db_conn.cursor()
  c.execute('SELECT url FROM PoC ')
  for row in c.fetchall():
    urlList.append(row[0])
  closePoCDB(db_conn)
  return urlList

# PoCinfo = {
#   "CVE": "CVE-2021-20837",
#   "url": "https://example.com",
#   "path": "/path/to/poc",
#   "description": "descriptionText",
#   "created_at": "2021-05-01 00:00:00",
#   "signatures": [
#     "/path/to/poc1",
#     "/path/to/poc2",
#   ]
# }
def insertPoCDB(PoCinfo, db_conn):
  if 'cve' not in PoCinfo or 'url' not in PoCinfo or 'created_at' not in PoCinfo or 'signatures' not in PoCinfo:
    return
  c = db_conn.cursor()
  # if cveid is not in CVE table, insert cveid info
  if PoCinfo['CVE'] != 'None':
    c.execute('SELECT * FROM CVE WHERE cveid = ?', (PoCinfo['CVE'],))
    if not c.fetchone():
      cveInfo = getCVEinfo(PoCinfo['CVE'])
      if cveInfo:
        c.execute('INSERT INTO CVE VALUES (?, ?, ?, ?)', (PoCinfo['CVE'], cveInfo['CVSS'], cveInfo['CVSSAV'], ','.join(cveInfo['CWE'])))
        db_conn.commit()
  # if url is not in PoC table, insert PoC info and signatures
  c.execute('SELECT * FROM PoC WHERE url = ?', (PoCinfo['url'],))
  if not c.fetchone():
    c.execute('INSERT INTO PoC VALUES (NULL, ?, ?, ?, ?, ?, ?)', (PoCinfo['CVE'], PoCinfo['url'], PoCinfo['path'], PoCinfo['description'], PoCinfo['created_at'], datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    db_conn.commit()
    # insert signatures
    if PoCinfo['signatures']:
      c.execute('SELECT * FROM PoC WHERE url = ?', (PoCinfo['url'],))
      pocid = c.fetchone()[0]
      for signature in PoCinfo['signatures']:
        c.execute('INSERT INTO Signature VALUES (?, ?)', (signature, pocid))
        db_conn.commit()


# CVSS Base Score >= 7.0, Attack Vector = Network, CWE-78
# return newCVEs = {
#  "CVE-2021-20837": {
#   "CVSS": 7.5,
#   "PoC": [
#    "https://example.com",
#    "https://example.com",
#   ],
#   "Signatures": [
#    "/path/to/poc1",
#    "/path/to/poc2",
#   ],
#   "description": "descriptionText",
#  },
# }
def getnewPredictedPoC(db_conn):
  newCVEs = {}
  c = db_conn.cursor()
  c.execute('SELECT * FROM CVE WHERE cvss >= 7.0 AND cvssav = "Network" AND cwe LIKE "%CWE-78%" AND NOT EXISTS (SELECT * FROM Predicted WHERE CVE.cveid = Predicted.cveid)')
  for cverow in c.fetchall():
    newCVEs[cverow[0]] = {}
    newCVEs[cverow[0]]['CVSS'] = cverow[1] # CVSS Base Score
    c.execute('SELECT * FROM PoC WHERE cveid = ?', (cverow[0],))
    newCVEs[cverow[0]]['PoC'] = []
    newCVEs[cverow[0]]['description'] = ''
    for row in c.fetchall():
      newCVEs[row[1]]['PoC'].append(row[2])
      newCVEs[row[1]]['description'] += row[4] + '\n\n'
    newCVEs[cverow[0]]['description'] = newCVEs[cverow[0]]['description'].rstrip('\n\n')
    c.execute('SELECT * FROM Signature WHERE pocid IN (SELECT pocid FROM PoC WHERE cveid = ?)', (cverow[0],))
    newCVEs[cverow[0]]['Signatures'] = []
    for row in c.fetchall():
      newCVEs[cverow[0]]['Signatures'].append(row[0])
  return newCVEs



def createPoCDB():
  if os.path.isfile(os.path.join(thisPath, '../PoC.db')):
    return
  conn = sqlite3.connect(os.path.join(thisPath, '../PoC.db'))
  c = conn.cursor()
  # PoC: pocid, cveid, url, path, description, created_at, found_at 
  c.execute('CREATE TABLE PoC (pocid INTEGER PRIMARY KEY AUTOINCREMENT, cveid TEXT, url TEXT, path TEXT, description TEXT, created_at TEXT, found_at TEXT)')
  # CVE: cveid, CVSS, CVSSAV, CWE
  c.execute('CREATE TABLE CVE (cveid TEXT PRIMARY KEY, CVSS REAL, CVSSAV TEXT, CWE TEXT)')
  # Signature: signature, pocid
  c.execute('CREATE TABLE Signature (signature TEXT PRIMARY KEY, pocid INTEGER)')
  # predicted: cveid, pocid, predicted_at
  c.execute('CREATE TABLE Predicted (cveid TEXT, pocid INTEGER, predicted_at TEXT)')
  conn.commit()
  # print tables list
  c.execute('SELECT name FROM sqlite_master WHERE type="table"')
  print(c.fetchall())
  conn.close()


def notifySlack(PoCInfo):
  webHookURL = os.environ.get('SLACK_WEBHOOK_URL')
  if not webHookURL:
    print('SLACK_WEBHOOK_URL is not set in .env')
    return
  txt = f'⚠ New PoC was released {PoCInfo["CVE-ID"]}\n'
  txt += f'CVSS Base Score: {PoCInfo["CVSS"]}\n\n'
  txt += 'PoC:\n'
  for url in PoCInfo['PoC']:
    txt += f'<{url}>\n'
  if PoCInfo['Signatures']:
    txt += '\nSignature:\n'
    for signature in PoCInfo['Signatures']:
      txt += f'{signature}\n'
  requests.post(webHookURL, 
    data=json.dumps({
      'text': txt,
      'link_names': 1,
    }),)

createPoCDB()

