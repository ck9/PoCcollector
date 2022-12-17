import os, glob, json, sys, re, time, requests
from datetime import datetime 
from dotenv import load_dotenv
from progressbar import ProgressBar
from bs4 import BeautifulSoup as bs
sys.path.append(os.path.join(os.path.dirname(__file__), '../'))
from functions import *

thisDir = os.path.dirname(os.path.abspath(__file__))

def update_pstorm():
  if not os.path.isdir(os.path.join(thisDir, 'PoC-in-PacketStorm')):
    os.mkdir(os.path.join(thisDir, 'PoC-in-PacketStorm'))
  print("Downloading PoC from PacketStorm...")
  html = requests.get('https://packetstormsecurity.com/files/tags/exploit/').text
  max_page = int(re.findall(r'Page 1 of ([0-9,]+)', html)[0].replace(',', ''))
  p = 4
  if os.path.isfile(os.path.join(thisDir, 'PoC-in-PacketStorm.json')):
    with open(os.path.join(thisDir, 'PoC-in-PacketStorm.json'), 'r') as f:
      PoCdata = json.load(f)
  else:
    PoCdata = {}
  with ProgressBar(max_value=max_page) as pbar:
    isFinish = False
    while isFinish == False:
      html = requests.get(f"https://packetstormsecurity.com/files/tags/exploit/page{p}/").text
      soup = bs(html, 'html.parser')
      # #m > dl
      for item in soup.select('#m > dl'):
        '''<dl id="F170271" class="file first">
            <dt><a class="ico text-plain" href="/files/170271/Bangresta-1.0-SQL-Injection.html" title="Size: 1.1 KB">Bangresta 1.0 SQL Injection</a></dt>
            <dd class="datetime">Posted <a href="/files/date/2022-12-16/" title="14:16:13 UTC">Dec 16, 2022</a></dd>
            <dd class="refer">Authored by <a href="/files/author/14758/" class="person">nu11secur1ty</a></dd>
            <dd class="detail"><p>Bangresta version 1.0 suffers from a remote SQL injection vulnerability.</p></dd>
            <dd class="cve"><span>advisories</span> | <a href="/files/cve/CVE-2020-25736">CVE-2020-25736</a></dd>
            <dd class="tags"><span>tags</span> | <a href="/files/tags/exploit">exploit</a>, <a href="/files/tags/remote">remote</a>, <a href="/files/tags/sql_injection">sql injection</a></dd>
            <dd class="md5"><span>SHA-256</span> | <code>6e637787eb6b3ed2d785900a186d5cd5989d7cf6482606330db770e979bcd9ab</code></dd>
            <dd class="act-links"><a href="/files/download/170271/bangresto10-sql.txt" title="Size: 1.1 KB" rel="nofollow">Download</a>  | <a href="/files/favorite/170271/" class="fav" rel="nofollow">Favorite</a> | <a href="/files/170271/Bangresta-1.0-SQL-Injection.html">View</a></dd>
        </dl>'''
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
        # <dd class="act-links"><a href="/files/download/170271/bangresto10-sql.txt" title="Size: 1.1 KB" rel="nofollow">Download</a>  | <a href="/files/favorite/170271/" class="fav" rel="nofollow">Favorite</a> | <a href="/files/170271/Bangresta-1.0-SQL-Injection.html">View</a></dd>
        filePathAtag = item.select_one('dd.act-links > a')
        if not filePathAtag or filePathAtag.text != 'Download':
          continue
        fileExt = os.path.splitext(filePathAtag.get('href'))[1]
        filePath = thisDir + '/PoC-in-PacketStorm/' + fileID + fileExt
        fileURL = 'https://packetstormsecurity.com' + filePathAtag.get('href')
        with open(filePath, 'wb') as f:
          f.write(requests.get(fileURL).content)
        PoCdata[fileID] = {
          "url": PoCurl,
          "cve": cve,
          "description": description,
          "created_at": date.strftime('%Y-%m-%dT%H:%M:%SZ'),
          "file": filePath,
        }
      nv = soup('a', text='Next')
      if not nv:
        isFinish = True
        break
      else:
        p += 1
        pbar.update(p)
        time.sleep(1)

  with open(thisDir + '/PoC-in-PacketStorm.json', 'w') as f:
    json.dump(PoCdata, f, indent=2)
  
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
        "signatures": getSignFromPoC(PoCdata['path'])
      }
      insertPoCDB(db_conn, PoCinfo)
  closePoCDB(db_conn)