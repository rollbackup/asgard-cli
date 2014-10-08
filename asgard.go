package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Unknwon/cae/zip"
	"github.com/franela/goreq"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Asgard struct {
	ApiUrl string
}

type CheckRequest struct {
	Hashlist []string `json:"hash"`
}

type CheckResult struct {
	Result []int
}

type ScanZipResult struct {
	Match   bool
	Verdict map[string]string
}

func (a *Asgard) Check(hashlist []string) (result []int, err error) {
	req := goreq.Request{
		Uri:         a.ApiUrl + "/check",
		Method:      "POST",
		Body:        CheckRequest{Hashlist: hashlist},
		ContentType: "application/json",
	}
	resp, err := req.Do()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("asgard check http error: code=%d\n", resp.StatusCode)
	}

	var res CheckResult
	resp.Body.FromJsonTo(&res)
	return res.Result, nil
}

func (a *Asgard) ScanZip(zip io.Reader) (*ScanZipResult, error) {
	b := new(bytes.Buffer)
	bw := multipart.NewWriter(b)
	fw, err := bw.CreateFormFile("file", "scan.zip")
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(fw, zip)
	if err != nil {
		return nil, err
	}

	err = bw.Close()
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(a.ApiUrl+"/scan_zip", bw.FormDataContentType(), b)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	res := &ScanZipResult{}
	if err := json.Unmarshal(body, res); err != nil {
		return nil, err
	}

	return res, nil
}

func main() {
	t := time.Now()
	flag.Parse()
	zip.Verbose = false

	dir := flag.Arg(0)

	if dir == "" {
		log.Fatal("no directory given")
	}

	if st, err := os.Stat(dir); err != nil {
		log.Fatal(err)
	} else if !st.IsDir() {
		log.Fatal(dir + ": not a directory")
	}

	fmt.Print("Generate filelist... ")
	filelist := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		md5 := md5.New()
		io.Copy(md5, f)
		filehash := fmt.Sprintf("%x", md5.Sum(nil))
		filelist[filehash] = path
		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d files found\n", len(filelist))
	fmt.Println(time.Since(t))
	hashlist := make([]string, 0, len(filelist))
	pathlist := make([]string, 0, len(filelist))

	for k, v := range filelist {
		hashlist = append(hashlist, k)
		pathlist = append(pathlist, v)
	}

	fmt.Println("Check for known malware...")
	a := &Asgard{"https://asgardapi.com/wordpress/v1beta"}
	result, err := a.Check(hashlist)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(time.Since(t))

	b := new(bytes.Buffer)
	z := zip.New(b)
	unknown := 0

	for _, v := range result {
		if v < 0 {
			v = -v
			fname := pathlist[v-1]
			z.AddFile(fname, fname)
			unknown++
		} else {
			fmt.Printf("MALWARE %s\n", pathlist[v-1])
		}
	}
	z.Flush()
	fmt.Println(time.Since(t))

	if unknown > 0 {
		fmt.Println("Scan unknown files...")
		res, err := a.ScanZip(b)
		if err != nil {
			log.Fatal(err)
		}

		if res.Match {
			for f, verdict := range res.Verdict {
				fmt.Printf("%s\t%s\n", verdict, f)
			}
		}
		fmt.Println(time.Since(t))
	}
}
