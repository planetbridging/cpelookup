import sys
from prettytable import PrettyTable


CpeCol = ["Number","Cpe","CVE","Exploits"]
CveCol = ["Number","Cve","AttType","Score", "AVec", "AComp", "Auth", "ConIm", "InImpa"]
KaliCol = ["id","file","description","date","author","type","platform","port"]

class ObjCpelookup:
    def __init__(self):
        self.InputData = ""
        self.Running()
        
    
    def Running(self):
        while True:
            SInput = ""
            NInput = ""
            EInput = ""
            InputData = ""
            if sys.version_info[0] < 3:
                InputData = str(raw_input("cpelookup: "))
                #print(sys.version_info[0])
            else:
                InputData = str(input("cpelookup: "))
            
            print(InputData)
            
            if InputData == "q":
                break
            
            if "-s" in InputData:
                SInput = self.GetInput(InputData, "-s")
                
                
            if "-n" in InputData:
                NInput = self.GetInput(InputData, "-n")
                
            if "-e" in InputData:
                EInput = self.GetInput(InputData, "-e")
                
            if SInput != "" and NInput == "":
                tbl = self.ReadFileNFind("cpe_tbl.csv",SInput, CpeCol, "-s")
                print(tbl)
            elif SInput != "" and NInput != "":
                tbl = self.ReadFileNFind("cpe_tbl.csv",SInput, CpeCol, "-s")
                ifint = self.RepresentsInt(NInput)
                NumInput =int(NInput) 
                if  NumInput>= 0 and NumInput<=20:
                    print(tbl[NumInput])
                    
                if EInput == "t":
                    selcpe = self.GetSelectedItem(tbl[NumInput],"Cpe")
                    cvetbl = self.ReadFileNFind("CVEYear_tbl.csv",selcpe,CveCol,"-e")
                    #print(cvetbl)
                    cvelst = self.GetSelectedItems(cvetbl,"Cve")
                    kalitbl = self.ReadFileNFind("cve_kali_tbl.csv",cvelst,["emty"],"-k")
                    lstid = self.GetKaliID(kalitbl)
                    foundexploits = self.ReadFileNFind("files_exploits.csv",lstid,KaliCol,"-fe")
                    print(foundexploits)
    
    def GetKaliID(self,tbl):
        lstid = []
        for row in tbl:
            row.border = False
            row.header = False
            item = row.get_string(fields=["emty"]).strip()
            iclean = item.replace('"', '')
            iclean = iclean.split(",")
            for ic in range(1,len(iclean)):
                if iclean[ic] != "":
                    lstid.append(iclean[ic])
        return lstid
    
    def GetSelectedItem(self,tbl,colitem):
        item = ""
        for row in tbl:
            row.border = False
            row.header = False
            item = row.get_string(fields=[colitem]).strip()
        return item
        
    def GetSelectedItems(self,tbl,colitem):
        item = []
        for row in tbl:
            row.border = False
            row.header = False
            item.append(row.get_string(fields=[colitem]).strip())
        return item
    
    def RepresentsInt(self,s):
        try: 
            int(s)
            return True
        except ValueError:
            return False
                        
    def GetInput(self, InputData, icmd):
        cmds = InputData.split(" ")
        sinput = ""
        snext = False
      
        for c in cmds:
        
            if snext:
                sinput = c
                break
                
            if c == icmd:
                snext = True
     
        return sinput
            
    def ReadFileNFind(self, file, find, cols, stype):
        OLength = 20
        OCount = 0
        tbl = PrettyTable()
        tbl.field_names = cols
        f = open(file, "r")
        
        for x in f:
            if OCount <= OLength:
                if stype == "-s":
                    xdata = x.replace('"', '')
                    xdata = xdata.split(",")
                    if find in xdata[0]:
                        ecount = int(xdata[2])
                        if ecount >= 1:
                            tbl.add_row([str(OCount)] + xdata)
                            OCount+=1
                elif stype == "-e":
                    xdata = x.replace('"', '')
                    xdata = xdata.split(",")
                    if find in xdata[10]:
                        tbl.add_row([str(OCount), xdata[0],xdata[1],xdata[2],xdata[3],xdata[4], xdata[5], xdata[6], xdata[7]])
                        OCount+=1
                elif stype == "-k":
                    #tbl.add_row(x.split(","))
                    xdata = x.replace('"', '')
                    xdata = xdata.split(",")
                    for cvefind in find:
                        #print(cvefind)
                        if cvefind.upper() in xdata[0].upper():
                            tbl.add_row([x])
                elif stype == "-fe":
                    xdata = x.replace('"', '')
                    xdata = xdata.split(",")
                    for cvefind in find:
                        if cvefind == xdata[0]:
                            #print(str(len(xdata)) + "|||" + str(len(cols)))
                            #print(x)
                            #tbl.add_row([x])
                            tbl.add_row([xdata[0],xdata[1],xdata[2],xdata[3],xdata[4],xdata[5],xdata[6],xdata[7]])
                    
        return tbl
            
    def LstCpe(self):
        pass
    

def main():
    print("CPELOOKUP")
    ocpe = ObjCpelookup()
    
if __name__ == "__main__":
    main()
    
    
    
