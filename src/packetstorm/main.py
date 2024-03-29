import os, glob, json, sys, re, time, requests
from datetime import datetime 
from dotenv import load_dotenv
from progressbar import ProgressBar
from bs4 import BeautifulSoup as bs
sys.path.append(os.path.join(os.path.dirname(__file__), '../'))
from functions import *

thisDir = os.path.dirname(os.path.abspath(__file__))
Myheader = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
}

def update_pstorm():
  if not os.path.isdir(os.path.join(thisDir, 'PoC-in-PacketStorm')):
    os.mkdir(os.path.join(thisDir, 'PoC-in-PacketStorm'))
  if os.path.isfile(os.path.join(thisDir, 'PoC-in-PacketStorm.json')):
    with open(os.path.join(thisDir, 'PoC-in-PacketStorm.json'), 'r') as f:
      PoCdata = json.load(f)
  else:
    PoCdata = {}
  '''
  print("Downloading PoC from PacketStorm...")
  html = requests.get('https://packetstormsecurity.com/files/tags/exploit/').text
  max_page = int(re.findall(r'Page 1 of ([0-9,]+)', html)[0].replace(',', ''))
  p = 1
  with ProgressBar() as pbar:
    isFinish = False
    while isFinish == False:
      html = requests.get(f"https://packetstormsecurity.com/files/tags/exploit/page{p}/").text
      soup = bs(html, 'html.parser')
      # #m > dl
      for item in soup.select('#m > dl'):

        fileID = item.get('id')
        if not fileID or fileID in PoCdata:
          if fileID in PoCdata:
            isFinish = True
          continue

        PoCurl = "https://packetstormsecurity.com"+item.select_one('dt > a').get('href')

        # <a href="/files/date/2022-12-16/" title="14:16:13 UTC">Dec 16, 2022</a>
        date = datetime.strptime(item.select_one('dd.datetime > a').text + ' ' + item.select_one('dd.datetime > a').get('title'), '%b %d, %Y %H:%M:%S %Z')

        # <p>Bangresta version 1.0 suffers from a remote SQL injection vulnerability.</p>
        if item.select_one('dd.detail > p'):
          description = item.select_one('dd.detail > p').text
        else:
          description = ""

        # <a href="/files/cve/CVE-2020-25736">CVE-2020-25736</a
        if item.select_one('dd.cve > a'):
          cve = item.select_one('dd.cve > a').text
        else:
          cve = "None"

        # <dd class="act-links"><a href="/files/download/170271/bangresto10-sql.txt" title="Size: 1.1 KB" rel="nofollow">Download</a></dd>
        filePathAtag = item.select_one('dd.act-links > a')

        if not filePathAtag or filePathAtag.text != 'Download':
          continue
        fileExt = os.path.splitext(filePathAtag.get('href'))[1]
        filePath = thisDir + '/PoC-in-PacketStorm/' + fileID + fileExt
        fileURL = 'https://packetstormsecurity.com' + filePathAtag.get('href')
        with open(filePath, 'wb') as f:
          f.write(requests.get(fileURL, headers=Myheader).content)
        PoCdata[fileID] = {
          "url": PoCurl,
          "cve": cve,
          "description": description,
          "created_at": date.strftime('%Y-%m-%d %H:%M:%S'),
          "file": filePath,
        }
        p += 1
        pbar.update(p)
        time.sleep(100)
      nv = soup('a', text='Next')
      if not nv:
        isFinish = True
        break
      else:
        time.sleep(100)

  with open(thisDir + '/PoC-in-PacketStorm.json', 'w') as f:
    json.dump(PoCdata, f, indent=2)

  '''
  
  # insert new PoC data to DB
  db_conn = connectPoCDB()
  PoCurlList = getPoCurlList(db_conn)
  print("Importing to Database...")
  pCnt = 0
  with ProgressBar(max_value=len(PoCdata)) as pbar:
    for fileID, PoC in PoCdata.items():
      pCnt += 1
      pbar.update(pCnt)
      if PoC['url'] in PoCurlList:
        continue
      PoCurlList.append(PoC['url'])
      PoCinfo = {
        "cve": PoC['cve'],
        "url": PoC['url'],
        "path": PoC['file'],
        "description": PoC['description'],
        "created_at": PoC['created_at'],
        "signatures": getSignFromPoC(PoC['file'])
      }
      insertPoCDB(PoCinfo, db_conn)
  closePoCDB(db_conn)
