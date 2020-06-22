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
)



/*-------------------------------------------------------------------
structs
--------------------------------------------------------------------*/
//kali_exploits.csv
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

/*-------------------------------------------------------------------
arrays
--------------------------------------------------------------------*/
var lstExploits [] obj_file_exploits
var lstShells [] obj_file_exploits
var lstCveId [] obj_exploitdb_mapping

func main() {

	downloadmanager.StartDownload()
	//fmt.Println("Download Status: ", dl)

	lst_exploits := readCsv("downloads/files_exploits.csv")
  loadFileExploits(lst_exploits)

  lst_shells := readCsv("downloads/files_shellcodes.csv")
  loadFileShells(lst_shells)

  loadExploitMapping()
}

/*-------------------------------------------------------------------
load arrays
--------------------------------------------------------------------*/
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
			log.Fatal(err)
		}
		//fmt.Printf("Question: %s Answer %s\n", record[0], record[1])
    lstfile = append(lstfile, record)
    //fmt.Println(reflect.TypeOf(record[0]))

	}
  fmt.Println("finished: " + file)
  return lstfile
}
