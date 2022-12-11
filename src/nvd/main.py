import os, json

thisDir = os.path.dirname(__file__)

def update_nvd():
    if not os.path.isdir(thisDir + "/NVD-Database"):
        print("Cloning NVD-Database repository")
        os.system(
          "cd %s; git clone https://github.com/nomi-sec/NVD-Database.git" % thisDir
        )
    else:
        print("Updating NVD-Database repository")
        os.system("cd %s/NVD-Database; git pull" % thisDir)

def getCVEinfo(cve):
    try:
        with open(thisDir + f"/NVD-Database/{cve[4:8]}/{cve}.json", "r") as f:
            NVDinfo = json.load(f)
            cveInfo = {}
            cveInfo["CWE"] = getCWE(NVDinfo)
            cveInfo["CVSS"] = getCVSS(NVDinfo)
            cveInfo["CVSSAV"] = getCVSSAV(NVDinfo)
            cveInfo["NVDpubdate"] = getNVDpubdate(NVDinfo)
            return cveInfo
    except FileNotFoundError:
        print(f"{cve} NVD info not found (FileNotFoundError)")
        return None

def getCWE(NVDinfo):
    try:
        CWEList = []
        for cwe in NVDinfo["cve"]["problemtype"]["problemtype_data"][0]["description"]:
            CWEList.append(cwe["value"])
        return CWEList
    except KeyError:
        cve = NVDinfo["cve"]["CVE_data_meta"]["ID"]
        print(f"{cve} CWE info not found (KeyError)")
        return None

def getCVSS(NVDinfo):
    try:
        return float(NVDinfo["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
    except KeyError:
        try:
            return NVDinfo["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
        except KeyError:
            cve = NVDinfo["cve"]["CVE_data_meta"]["ID"]
            print(f"{cve} CVSS info not found (KeyError)")
            return None
    except TypeError:
        return None

def getCVSSAV(NVDinfo):
    try:
        return NVDinfo["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
    except KeyError:
        try:
            return NVDinfo["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
        except KeyError:
            cve = NVDinfo["cve"]["CVE_data_meta"]["ID"]
            print(f"{cve} CVSS info not found (KeyError)")
            return None
    except TypeError:
        return None

def getNVDpubdate(NVDinfo):
    try:
        return NVDinfo["publishedDate"]
    except KeyError:
        cve = NVDinfo["cve"]["CVE_data_meta"]["ID"]
        print(f"{cve} NVD publish date info not found (KeyError)")
        return None