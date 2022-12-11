import os, re

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
