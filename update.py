from src.functions import *
from src.nvd.main import update_nvd
from src.github.main import update_github
from src.exploitdb.main import update_edb
from src.packetstorm.main import update_pstorm

def updateDB():
  print("  ## Update NVD ##  ")
  update_nvd()
  print("  ## Update GitHub ##  ")
  update_github()
  print("  ## Update ExploitDB ##  ")
  update_edb()
  print("  ## Update PacketStorm ##  ")
  update_pstorm()

def update():
  print("  ## Update ##  ")
  updateDB()
  print("  ## Update Finished ##  ")
  db_conn = connectPoCDB()
  newCVEs = getnewPredictedPoC(db_conn)
  print(f"  ## New CVE: {len(newCVEs)} ##  ")
  for cve in newCVEs:
    print(cve)
    newCVEs[cve]["CVE-ID"] = cve
    # notifySlack(newCVEs[cve])

if __name__ == "__main__":
  update()