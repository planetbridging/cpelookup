import json
import io


class ObjNVDYear:
  def __init__(self,
  cve,
  year,
  accessVector,
  accessComplexity,
  authentication,
  confidentialityImpact,
  integrityImpact,
  availabilityImpact,
  baseScore,
  description,
  lstcpe):
    self.cve = cve
    self.year = year
    self.accessVector = accessVector
    self.accessComplexity = accessComplexity
    self.authentication = authentication
    self.confidentialityImpact = confidentialityImpact
    self.integrityImpact = integrityImpact
    self.availabilityImpact = availabilityImpact
    self.baseScore = baseScore
    self.description = description
    self.lstcpe = lstcpe

def Clean(item):
    item = item.replace(":*","")
    item = item.replace("''","")
    item = item.replace('"','')
    item = item.replace(",","")
    item = item.replace("\n","")
    return item

def TryValue(data, key):
    try:
         return data[key]
    except KeyError:
         return ""



def ReadFile(year,data):
    LstObjNVDYear = []
    for (k, v) in data.items():
       #print("Key: " + k)
       if k == "CVE_Items":
           for cve in v:
               lstcpe = []
               accessVector = ""
               accessComplexity = ""
               authentication = ""
               confidentialityImpact = ""
               integrityImpact = ""
               availabilityImpact = ""
               baseScore = ""
               description = ""
               cveid = cve["cve"]["CVE_data_meta"]["ID"]

               #print(k)
               #print(len(v))

               #print(cve["cve"]["CVE_data_meta"]["ID"])
               #print(len(v[0]["configurations"]["nodes"]))

               try:
                    accessVector = cve["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
                    accessComplexity = cve["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"]
                    authentication = cve["impact"]["baseMetricV2"]["cvssV2"]["authentication"]
                    confidentialityImpact = cve["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"]
                    integrityImpact = cve["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"]
                    availabilityImpact = cve["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"]
                    baseScore = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]

               except KeyError:
                    pass

               try:
                   description = cve["cve"]["description"]["description_data"][0]["value"]
                   description = Clean(description)
                   #if "," in description:
                    #   description = description.replace(",","")
               except KeyError:
                   pass

               try:
                    for nodes in cve["configurations"]["nodes"]:
                        for cpe_match in nodes["cpe_match"]:
                            lstcpe.append(Clean(cpe_match["cpe23Uri"]))
               except KeyError:
                    pass

               Objnvdy = ObjNVDYear(
                    cveid,
                    year,
                    accessVector,
                    accessComplexity,
                    authentication,
                    confidentialityImpact,
                    integrityImpact,
                    availabilityImpact,
                    str(baseScore),
                    description,lstcpe)
               LstObjNVDYear.append(Objnvdy)

    ExportToCsv(LstObjNVDYear,year)

def MergeArray(lst):
    row = ""
    for l in lst:
        item = l + ":::"
        row += item
    row = row[:-3]
    row += " \n"
    return row

def ExportToCsv(LstObjNVDYear,year):
    print("saving: ",year)
    file1 = io.open("downloads/nvdcve_"+str(year)+".csv","w",encoding='utf-8')#write mode
    file1.write("CVEName,Year,Score,AccessVector,AccessComplexity,Authentication,ConfidentialityImpact,IntegrityImpact,AvailabilityImpact,Description,LstCpe \n")
    for y in LstObjNVDYear:

        lstmerge = MergeArray(y.lstcpe)
        file1.write(
            y.cve + "," +
            str(y.year) + "," +
            y.baseScore + "," +
            y.accessVector + "," +
            y.accessComplexity + "," +
            y.authentication + "," +
            y.confidentialityImpact + "," +
            y.integrityImpact + "," +
            y.availabilityImpact + "," +
            y.description + "," + lstmerge
        )
    file1.close()

def ReadAllYears():
    for x in range(2002, 2021):
        with open('downloads/nvdcve-1.1-'+str(x)+'.json',encoding="utf8") as f:
            data = json.load(f)
            ReadFile(x,data)

if __name__ == "__main__":
        ReadAllYears()
        #ExportToCsv()
