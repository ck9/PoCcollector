import re, os, sys
thisPath = os.path.dirname(__file__)
sys.path.append(os.path.join(thisPath, 'src'))
from functions import cve2yaml

cve = input('Enter CVE-ID: ')
if not re.match(r'^CVE-\d{4}-\d{4,}$', cve):
  print('Invalid CVE-ID')
  exit(1)

print ("\n"+cve2yaml(cve))