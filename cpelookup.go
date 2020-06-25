package main

import (
	//"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
  "io/ioutil"
  "encoding/json"
   "reflect"
	"pack/downloadmanager"
	"strings"
	//"time"
	"sync"
)



/*-------------------------------------------------------------------
structs
--------------------------------------------------------------------*/
type obj_file_exploits struct{
  id string
  file string
  description string
  date string
  author string
  f_type string
  platform string
  port string
}

type obj_exploitdb_mapping struct{
  cve string
  id [] string
}

type obj_cve struct{
  cve string
  attack_type string
  score string
  access_vector string
  access_complexity string
  authentication string
  confidentiality_impact string
  integrity_impact string
	availability_impact string
	description string
	cpe_lst [] string
}

/*-------------------------------------------------------------------
arrays
--------------------------------------------------------------------*/
var lstExploits [] obj_file_exploits
var lstShells [] obj_file_exploits
var lstCveId [] obj_exploitdb_mapping
var lstCve[] obj_cve
var lstAttackTypes[] string

func main() {
	//start := time.Now()
	downloadmanager.StartDownload()
	//fmt.Println("Download Status: ", dl)

	lst_exploits := readCsv("downloads/files_exploits.csv")
  loadFileExploits(lst_exploits)

  lst_shells := readCsv("downloads/files_shellcodes.csv")
  loadFileShells(lst_shells)

  loadExploitMapping()
	loadCsvNvd()
	loadAttackTypes()
	sortAttackType()
	//compareOldNew()
	//t := time.Now()
	//elapsed := t.Sub(start)
	//fmt.Println("Loading Time: ", elapsed)
}

func percentageChange(count, total int) float64 {
	return (float64(count) * float64(100)) / float64(total)
}
/*-------------------------------------------------------------------
sort arrays
--------------------------------------------------------------------*/

func sortAttackType(){
	count := 0
	total := len(lstCve)
	nocpe := 0
	for c := range lstCve{
		if len(lstCve[c].cpe_lst) == 0{
			count += 1
			nocpe +=1
		}else{
			for at := range lstAttackTypes {
				if strings.Contains(lstCve[c].description, lstAttackTypes[at]){
					count += 1
					break
				}
			}
		}
	}
	fmt.Println("Categorized", count, "/" , total, " or ", percentageChange(count,total), "%")
	//fmt.Println("No Cpe: ", nocpe)
}

/*-------------------------------------------------------------------
load arrays
--------------------------------------------------------------------*/

func loadAttackTypes(){
	lstAttackTypes = append(lstAttackTypes, "buffer overflow")
	lstAttackTypes = append(lstAttackTypes, "denial of service")
	lstAttackTypes = append(lstAttackTypes, "heap overflow")
	lstAttackTypes = append(lstAttackTypes, "sql injection")
	lstAttackTypes = append(lstAttackTypes, "remote attackers to execute")
	lstAttackTypes = append(lstAttackTypes, "directory traversal vulnerability")
	lstAttackTypes = append(lstAttackTypes, "remote attackers to read")
	lstAttackTypes = append(lstAttackTypes, "xss")
	lstAttackTypes = append(lstAttackTypes, "cross-site scripting")
	lstAttackTypes = append(lstAttackTypes, "cross site scripting")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to inject")
	lstAttackTypes = append(lstAttackTypes, "allows remote authenticated")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to use a certificate")
	lstAttackTypes = append(lstAttackTypes, "stack-based buffer overflow")
	lstAttackTypes = append(lstAttackTypes, "stack based buffer overflow")
	lstAttackTypes = append(lstAttackTypes, "allows local users to bypass")
	lstAttackTypes = append(lstAttackTypes, "allows local users to obtain")
	lstAttackTypes = append(lstAttackTypes, "cross-site request")
	lstAttackTypes = append(lstAttackTypes, "cross site request")
	lstAttackTypes = append(lstAttackTypes, "allows local users to expose")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to gain root")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to monitor")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to trick")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to view")
	lstAttackTypes = append(lstAttackTypes, "heap corruption")
	lstAttackTypes = append(lstAttackTypes, "allows local users to gain privileges")
	lstAttackTypes = append(lstAttackTypes, "allows local users to overwrite")
	lstAttackTypes = append(lstAttackTypes, "allows remote attackers to trigger memory corruption or possibly execute")
	lstAttackTypes = append(lstAttackTypes, "possibly execute")
	lstAttackTypes = append(lstAttackTypes, "allow remote attackers to modify")
	lstAttackTypes = append(lstAttackTypes, "privilege escalation")
	lstAttackTypes = append(lstAttackTypes, "remote attacker")
	lstAttackTypes = append(lstAttackTypes, "remote bypass")
	lstAttackTypes = append(lstAttackTypes, "remote code execution")
	lstAttackTypes = append(lstAttackTypes, "elevation of privilege")



}

func loadFileExploits(lst [][]string){
  for i := range lst {
    obj_fe := obj_file_exploits{
      id: lst[i][0],
      file: lst[i][1],
      description: lst[i][2],
      date: lst[i][3],
      author: lst[i][4],
      f_type: lst[i][5],
      platform: lst[i][6],
      port: lst[i][7],
    }
    lstExploits = append(lstExploits,obj_fe)
  }
}

func loadFileShells(lst [][]string){
  for i := range lst {
    obj_fe := obj_file_exploits{
      id: lst[i][0],
      file: lst[i][1],
      description: lst[i][2],
      date: lst[i][3],
      author: lst[i][4],
      f_type: lst[i][5],
      platform: lst[i][6],
    }
    lstShells = append(lstShells,obj_fe)
  }
}

func loadExploitMapping(){
  jsonFile, err := os.Open("downloads/exploitdb_mapping_cve.json")
  // if we os.Open returns an error then handle it
  if err != nil {
      fmt.Println(err)
  }
  defer jsonFile.Close()
  byteValue, _ := ioutil.ReadAll(jsonFile)
  var result map[string]interface{}
  json.Unmarshal([]byte(byteValue), &result)
  for key, items := range result {
    var dynitems [] string

    //fmt.Println(result[key])

    //fmt.Println(reflect.TypeOf(result[key]))
    //fmt.Println(key)
    object := reflect.ValueOf(items)
    for i := 0; i < object.Len(); i++ {
      str := fmt.Sprintf("%v", object.Index(i).Interface())
  		dynitems = append(dynitems, str)
      //fmt.Println(object.Index(i))
      //fmt.Println(object.Index(i).Interface())
  	}
    obj_mapping := obj_exploitdb_mapping{
      cve: key,
      id: dynitems,
    }
    lstCveId = append(lstCveId,obj_mapping)
  }

  fmt.Println("finished: exploitdb_mapping_cve.json")
}

func loadCsvNvd(){

	years := downloadmanager.GetYears()
	for y := range years {
		fmt.Println("Loading: ", years[y])
		if _, err := os.Stat("downloads/nvdcve_"+years[y]+".csv"); err == nil {
		  // path/to/whatever exists
			csvdata := readCsv("downloads/nvdcve_"+years[y]+".csv")

			for d := range csvdata{
				if d > 0{
					var lstdatasplit [] string
					if strings.Contains(csvdata[d][10],"cpe"){
						lstdatasplit = strings.Split(csvdata[d][10],":::")
					}
					obj_cveitem := obj_cve{
						cve: csvdata[d][0],
				    attack_type: "",
				    score: csvdata[d][2],
				    access_vector: csvdata[d][3],
				    access_complexity: csvdata[d][4],
				    authentication: csvdata[d][5],
				    confidentiality_impact: csvdata[d][6],
				    integrity_impact: csvdata[d][7],
				  	availability_impact: csvdata[d][8],
				  	description: csvdata[d][9],
				  	cpe_lst: lstdatasplit,
				  }
				  lstCve = append(lstCve,obj_cveitem)
				}
			}
			fmt.Println("CVE's Loaded: ",len(lstCve))
		} else if os.IsNotExist(err) {
		  // path/to/whatever does *not* exist
			fmt.Println("can't find nvd csv")
		}
	}

}

func compareOldNew(){
	var wg sync.WaitGroup
	old := readCsv("other/CVEYear_tbl.csv")
	for o := range old{
		if o > 0{
			wg.Add(1)
			go findOld(&wg,old[o])
		}
	}
}

func findOld(wg *sync.WaitGroup, old [] string){
	defer wg.Done()
	for c := range lstCve{
		if strings.ToUpper(old[0]) == lstCve[c].cve{
			lstCve[c].attack_type = old[1]
			break
		}
	}
	fmt.Println("Main: Waiting for workers to finish")
	wg.Wait()
	fmt.Println("Main: Completed")
}

/*-------------------------------------------------------------------
io
--------------------------------------------------------------------*/

func readCsv(file string) [][]string{
  var lstfile [][]string
  csvfile, err := os.Open(file)
  if err != nil {
    log.Fatalln("Couldn't open the csv file", err)
  }
  r := csv.NewReader(csvfile)
  for {
		// Read each record from csv
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("sad face")
			log.Fatal(err)
		}
		//fmt.Printf("Question: %s Answer %s\n", record[0], record[1])
    lstfile = append(lstfile, record)
    //fmt.Println(reflect.TypeOf(record[0]))

	}
  fmt.Println("finished: " + file)
  return lstfile
}
