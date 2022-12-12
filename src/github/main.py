import os, glob, json

thisDir = os.path.dirname(os.path.abspath(__file__))

def update_github():
  if not os.path.isdir(os.path.join(thisDir, 'PoC-in-GitHub')):
    print("Cloning exploit-database repository")
    os.system(
        "cd %s; git clone https://github.com/nomi-sec/PoC-in-GitHub.git" % thisDir
    )
  PoCdata = {}
  yearList = glob.glob(os.path.join(thisDir, 'PoC-in-GitHub/*'))
  yearList = [os.path.basename(year) for year in yearList]
  yearList = [year for year in yearList if year.isdigit()]
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
            "created_at": data['created_at'],
          })

  with open(os.path.join(thisDir, 'github_PoC.json'), 'w') as f:
    json.dump(PoCdata, f, indent=2)

