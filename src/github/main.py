import os, glob, json, sys
from datetime import datetime
from dotenv import load_dotenv
from progressbar import ProgressBar
sys.path.append(os.path.join(os.path.dirname(__file__), '../'))
from functions import *

thisDir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(thisDir, '../.env'))

def update_github():
  if not os.path.isdir(os.path.join(thisDir, 'PoC-in-GitHub')):
    print("Cloning exploit-database repository")
    os.system(
        "cd %s; git clone https://github.com/nomi-sec/PoC-in-GitHub.git" % thisDir
    )
  else:
    print("Updating exploit-database repository")
    os.system(
        "cd %s; cd PoC-in-GitHub; git pull" % thisDir
    )
  PoCdata = {}
  yearList = glob.glob(os.path.join(thisDir, 'PoC-in-GitHub/*'))
  yearList = [os.path.basename(year) for year in yearList]
  yearList = [year for year in yearList if year.isdigit()]
  pLen = 0
  for year in yearList:
    CVEList = glob.glob(os.path.join(thisDir, 'PoC-in-GitHub/%s/*' % year))
    for CVEjsonPath in CVEList:
      CVE = os.path.basename(CVEjsonPath).replace('.json', '')
      PoCdata[CVE] = []
      with open(CVEjsonPath, 'r') as f:
        PoCList = json.load(f)
        for data in PoCList:
          PoCdata[CVE].append({
            "full_name": data['full_name'],
            "url": data['html_url'],
            "description": data['description'],
            "created_at": datetime.strptime(data['created_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S'),
          })
          pLen += 1
  with open(os.path.join(thisDir, 'github_PoC.json'), 'w') as f:
    json.dump(PoCdata, f, indent=2)
  
  # insert new PoC data to DB
  db_conn = connectPoCDB()
  PoCurlList = getPoCurlList(db_conn)
  print("Importing to Database...")
  pCnt = 0
  with ProgressBar(max_value=pLen) as pbar:
    for cve in PoCdata.keys():
      for data in PoCdata[cve]:
        pCnt += 1
        pbar.update(pCnt)
        if data['url'] in PoCurlList:
          continue
        if 'Satheesh575555/' in data['full_name']:
          continue
        PoCurlList.append(data['url'])
        PoCinfo = {
          "cve": cve,
          "url": data['url'],
          "path": "None",
          "description": data['description'],
          "created_at": data['created_at'],
          "signatures": [],
        }
        insertPoCDB(PoCinfo, db_conn)
  closePoCDB(db_conn)