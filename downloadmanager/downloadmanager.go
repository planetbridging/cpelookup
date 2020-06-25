package downloadmanager

import (
	"fmt"
	"io"
	"net/http"
	"os"
  "archive/zip"
  "path/filepath"
  "strings"
  "log"
)

type obj_Download struct{
  location string
  name string
}

var years [] string

var lstfiles [] obj_Download


func GetYears()[] string{
	years := []string{
    "2002",
    "2003",
    "2004",
    "2005",
    "2006",
    "2007",
    "2008",
    "2009",
    "2010",
    "2011",
    "2012",
    "2013",
    "2014",
    "2015",
    "2016",
    "2017",
    "2018",
    "2019",
    "2020",
  }
	return years;
}

func StartDownload(){
	GetYears()
  fmt.Println("Loading: " , years)

  addObj("exploitdb_mapping_cve.json","https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping_cve.json")
  addObj("files_shellcodes.csv","https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_shellcodes.csv")
  addObj("files_exploits.csv","https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv")

  for y := range years {
    addObj("nvdcve-1.1-"+years[y]+".json.zip", "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+years[y]+".json.zip")
  }

  for obj := range lstfiles {
    found := Exists("downloads/" + lstfiles[obj].name)
    if !found{
      fmt.Println("downloading: " + lstfiles[obj].name)
      prepareFileDownload(lstfiles[obj])
    }else{
      if strings.HasSuffix(lstfiles[obj].name, ".zip"){
        //unzipfound := Exists("downloads/" + lstfiles[obj].name)
        //fmt.Println("unzipping: ", lstfiles[obj].name)
        unZipItems("downloads/" + lstfiles[obj].name)
      }
    }
  }
  //unZipItems()
  fmt.Println("Downloading Finished")
}

func unZipItems(fn string)string{
  files, err := Unzip(fn, "downloads")
    if err != nil {
        log.Fatal(err)
    }

    return "Unzipped:\n" + strings.Join(files, "\n")
}

func addObj(fn string, loc string){
  obj_dl := obj_Download{
    location: loc,
    name: fn,
  }
  lstfiles = append(lstfiles,obj_dl)
}

func prepareFileDownload(obj_dl obj_Download){
  fileUrl := obj_dl.location
	err := DownloadFile("downloads/" + obj_dl.name, fileUrl)
	if err != nil {
		panic(err)
	}
	fmt.Println("Downloaded: " + fileUrl)
}

func Exists(name string) bool {
    _, err := os.Stat(name)
    return !os.IsNotExist(err)
}

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory.
func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func Unzip(src string, dest string) ([]string, error) {

    var filenames []string

    r, err := zip.OpenReader(src)
    if err != nil {
        return filenames, err
    }
    defer r.Close()

    for _, f := range r.File {

        // Store filename/path for returning and using later on
        fpath := filepath.Join(dest, f.Name)

        // Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
        if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
            return filenames, fmt.Errorf("%s: illegal file path", fpath)
        }

        filenames = append(filenames, fpath)


        if Exists(filenames[0]){
          return filenames, err
        }else{

        }

        if f.FileInfo().IsDir() {
            // Make Folder
            os.MkdirAll(fpath, os.ModePerm)
            continue
        }

        // Make File
        if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
            return filenames, err
        }

        outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        if err != nil {
            return filenames, err
        }

        rc, err := f.Open()
        if err != nil {
            return filenames, err
        }

        _, err = io.Copy(outFile, rc)

        // Close the file without defer to close before next iteration of loop
        outFile.Close()
        rc.Close()

        if err != nil {
            return filenames, err
        }
    }
    return filenames, nil
}
