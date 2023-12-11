package scscanner

import (
	"bufio"
//	"bytes"
	"fmt"
	"net/url"
	"os"
	"sync"
	"pohek/printer"
	"pohek/helper"
	"log"
	"time"
    "math/rand"
	"strings"
	"path/filepath"
)

type SCScanner struct {
	Opts                  *Options
	Paths                 []string
	mu                    sync.Mutex
	Printer               *printer.Printer
	PathsNum              int
	Scanned               int
	Results               []string
	RootResponse          []*Response //second Response with Redirect enabled
	DummyResponses        []*Response
	HttpClient            *HTTPClient
	CheckResourcePath     string
	CheckResourceResponse *Response
	HostnameUrl           string
	DiffInaRow            int
	ErrorCount            int
	ForbiddenCount        int
	WasBanned             bool
	Payloads              []string
}

func (v *SCScanner) WriteResults() error {
	filename := strings.ReplaceAll(v.Opts.Hostname, ".", "_") + ".txt"
	path := filepath.Join(v.Opts.OutputDir, filename) 
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range v.Results {
		fmt.Fprintln(f, line)
	}
	return nil
}

func (v *SCScanner) addResult(result string) {
	fmt.Println(result)
	v.Results = append(v.Results, result)
}

func (v *SCScanner) ReadFileLines() error {
	if v.Opts.URLsFile { //using input file with crawled URLs
		file, err := os.Open(v.Opts.Wordlist)
		if err != nil {
			return err
		}
		defer file.Close()
		v.Paths = make([]string, 0)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			helper.SplitUrl(scanner.Text(), &v.Paths)
		}
		v.Paths = helper.Unique(v.Paths)
		v.PathsNum = len(v.Paths)
		//fmt.Println(v.Paths)
		return scanner.Err()
	} else {
		file, err := os.Open(v.Opts.Wordlist)
		if err != nil {
			return err
		}
		defer file.Close()
		v.Paths = make([]string, 0)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			v.Paths = append(v.Paths, scanner.Text())
		}
		v.PathsNum = len(v.Paths)
		return scanner.Err()
	}

}

func (v *SCScanner) initHttpClient() {
	v.HttpClient, _ = NewHTTPClient(v.Opts)
}

func (v *SCScanner) setHostnameUrl() {
	if v.Opts.Ssl {
		v.HostnameUrl = "https://" + v.Opts.Hostname
	} else {
		v.HostnameUrl = "http://" + v.Opts.Hostname
	}
}
func (v *SCScanner) makeDefaultResponses() {
	filtered_payloads := []string{}
	filtered_responses := []*Response{}
	dummy_path := "/gachimuchicheburek/"
	r, err := v.HttpClient.CreateResponse(v.HostnameUrl, "")
	if err != nil {
		log.Fatal(err)
		return
	}
	v.RootResponse = append(v.RootResponse, r)
	// v.HttpClient.SetRedirects(true)
	// r, _ = v.HttpClient.CreateResponse(v.HostnameUrl, "")
	// v.RootResponse = append(v.RootResponse, r)
	//v.CheckResourcePath = helper.ParseBody(bytes.NewReader(v.RootResponse[1].Body))
	//v.CheckResourceResponse, _ = v.HttpClient.CreateResponse(v.CheckResourcePath, v.CheckResourcePath)
	v.HttpClient.SetRedirects(false)
	dummy_traversal_urls := helper.AddTraversal(dummy_path, v.Payloads)
	for i, u := range dummy_traversal_urls {
		a, err := v.HttpClient.CreateResponse(v.HostnameUrl, u)
		if r.StatusCode == 403 {
			filtered_responses = append(filtered_responses, a)
			filtered_payloads = append(filtered_payloads, v.Payloads[i])
		} else if a.StatusCode == 403 {
			fmt.Println("Web app does not allow to use ", u, " in URL. This payload will be skipped")
		} else if err != nil {
			log.Fatal(err)
		} else {
			filtered_responses = append(filtered_responses, a)
			filtered_payloads = append(filtered_payloads, v.Payloads[i])
		}
	}
	v.DummyResponses = filtered_responses
	v.Payloads = filtered_payloads
	if (len(v.DummyResponses) == 0) || (len(v.Payloads) == 0) {
		fmt.Println("Web app does not allow to use traversal in any way. Program was stopped")
		os.Exit(3)
	}
}

func (v *SCScanner) worker(wg *sync.WaitGroup, urls_to_scan <-chan string) {
	// Уменьшаем контер горутин, когда выполнена таска
	defer wg.Done()
	//for loop используем чтобы читать данные из канала, когда их много
	for u := range urls_to_scan {
		u, _ := url.Parse(u)
		path := u.Path
		var onestepback_response *Response
		onestepback_path := helper.OneStepBackPath(path)
		dummy_path := path + "gachimuchicheburek/"
		//fmt.Println("Path is ", path, "back path is ", onestepback_path, "dummy_path is ", dummy_path)
		if (onestepback_path == "/") || (onestepback_path == " ") || (len(onestepback_path) == 0) {
			onestepback_response = v.RootResponse[0]
		} else {
			onestepback_response, _ = v.HttpClient.CreateResponse(v.HostnameUrl, onestepback_path)
		}
		v.Scanned++
		retries := v.Opts.Retry
		traversal_paths := helper.AddTraversal(path, v.Payloads)
		for c, url := range traversal_paths {
			var dummy_response *Response
			if !v.Opts.URLsFile {
				dummy_response = v.DummyResponses[c]
			} else {
				dummy_response, _ = v.HttpClient.CreateResponse(v.HostnameUrl, dummy_path)
			}
			for i := 0; i <= retries; i++ {
				resp, err := v.HttpClient.CreateResponse(v.HostnameUrl, url)
				v.mu.Lock()
				v.checkForBan(resp)
				if err != nil {
					if i < retries {
						v.mu.Unlock()
						continue
					}
					v.ErrorCount++
					if v.ErrorCount > 5 {
						fmt.Println("Web app responds with 5 errors in a row. The program was stopped")
						os.Exit(3)
					} else {
						v.Printer.PrintErr(v.HostnameUrl+url, err)
						v.Printer.PrintProg(v.PathsNum, v.Scanned)
						str := v.HostnameUrl+url
						v.addResult(str)
						rand.Seed(time.Now().UnixNano())
						min := 2
                        max := 5
    					n := rand.Intn(max - min + 1) + min
						time.Sleep(time.Duration(n)*time.Second)
						v.mu.Unlock()
						break
					}
					
				} else {
					v.ErrorCount = 0
					v.findDifference(resp, url, onestepback_response, dummy_response)
					// if v.Opts.IgnoreStatus {
					// 	v.findDifference(data, resp)
					// } else {
					// 	for _, code := range v.Opts.StatusCodes {
					// 		if code == resp.Status {
					// 			v.findDifference(data, resp)
					// 		}
					// 	}
					// }
					v.mu.Unlock()
					break
				}
			}
		}
		v.Printer.PrintProg(v.PathsNum, v.Scanned)
	}

}

// func (v *SCScanner) checkByClientResource(body io.Reader) {
// 	var links []string
// 	z := html.NewTokenizer(body)
// 	client := v.HttpClient
// 	client.EnableRedirects()
// 	for {
// 		tt := z.Next()
// 		switch tt {
// 		// case html.ErrorToken:
// 		// 	//todo: links list shoudn't contain duplicates
// 		// 	return links
// 		case html.StartTagToken, html.EndTagToken:
// 			token := z.Token()
// 			if "a" == token.Data {
// 				for _, attr := range token.Attr {
// 					if attr.Key == "href" {
// 						links = append(links, attr.Val)
// 					}

// 				}
// 			}

// 		}
// 		fmt.Println("Links: ", links)
// 	}
// }
func (v *SCScanner) findDifference(traversal_response *Response, URL string, onestepback_response *Response, dummy_response *Response) {
	// if v.Opts.CheckSize {
	// 	v.Printer.PrintProg(v.VHostsNum, v.Scanned)
	// 	if v.Opts.Size != resp.Size {
	// 		if v.Opts.Fuzzy {
	// 			ratio := LevenshteinRation(v.FuzzyTargetResponse.Body, resp.Body)
	// 			if ratio <= v.Opts.FuzzyRatio {
	// 				v.printResultsFuzzy(vhost, resp.Size, resp.Status, ratio)
	// 			}
	// 		} else {
	// 			v.printResults(vhost, resp.Size, resp.Status)
	// 		}
	// 	}
	// } else {
	// 	if v.Opts.Fuzzy {
	// 		ratio := LevenshteinRation(v.FuzzyTargetResponse.Body, resp.Body)
	// 		if ratio <= v.Opts.FuzzyRatio {
	// 			v.printResultsFuzzy(vhost, resp.Size, resp.Status, ratio)
	// 		}
	// 	} else {
	// 		v.printResults(vhost, resp.Size, resp.Status)
	// 	}
	// }
	if !v.Opts.URLsFile {
		if (traversal_response.StatusCode != onestepback_response.StatusCode) && (traversal_response.StatusCode != dummy_response.StatusCode) {
			// u, err := url.Parse(v.CheckResourcePath)
			// if err != nil {
			// 	panic(err)
			// }
			//fmt.Println(URL + u.Path)
			// traversal_body, _ := v.HttpClient.CreateResponse(v.HostnameUrl, u.Path)
			// if (v.CheckResourcePath != "") && (string(v.CheckResourceResponse.Body) != string(traversal_body.Body)) {
			// 	v.addResult(fmt.Sprintf("Status code and check resource differ for %s", URL))
			// 	v.DiffInaRow++
			// }
			fmt.Println(traversal_response.StatusCode, " ", onestepback_response.StatusCode, " ", dummy_response.StatusCode, " ")
			//fmt.Println(string(traversal_response.Body))
			v.addResult(fmt.Sprintf("Status code differs for %s", URL))
			v.DiffInaRow++
		}
		if (traversal_response.Server != onestepback_response.Server) && (traversal_response.Server != dummy_response.Server) {
			//fmt.Println(string(traversal_response.Body))
			v.addResult(fmt.Sprintf("Server header differs for %s", URL))
			v.DiffInaRow++
		}
		if (traversal_response.ContentType != onestepback_response.ContentType) && (traversal_response.ContentType != dummy_response.ContentType) {
			//fmt.Println(string(traversal_response.Body))
			v.addResult(fmt.Sprintf("Content-Type header differs for %s", URL))
			v.DiffInaRow++
		}
		// if (levenshteinRatio(traversal_response.Body, onestepback_response.Body) < 65) && (levenshteinRatio(traversal_response.Body, v.DummyResponse[c].Body)) < 65 {
		// 	return "Content of the pages differs"
		// }
	} else {
		if (traversal_response.StatusCode != onestepback_response.StatusCode) && (traversal_response.StatusCode != dummy_response.StatusCode) {
			// u, err := url.Parse(v.CheckResourcePath)
			// if err != nil {
			// 	panic(err)
			// }
			//fmt.Println(URL + u.Path)
			// traversal_body, _ := v.HttpClient.CreateResponse(v.HostnameUrl, u.Path)
			// if (v.CheckResourcePath != "") && (string(v.CheckResourceResponse.Body) != string(traversal_body.Body)) {
			// 	v.addResult(fmt.Sprintf("Status code and check resource differ for %s", URL))
			// } else {
			// 	v.addResult(fmt.Sprintf("Status code differs for %s", URL))
			// }
			v.addResult(fmt.Sprintf("Status code differs for %s", URL))
		}
		// if (traversal_response.Server != onestepback_response.Server) && (traversal_response.Server != dummy_response.Server) {
		// 	v.addResult(fmt.Sprintf("Server header differs for %s", URL))
		// }
		if (traversal_response.ContentType != onestepback_response.ContentType) && (traversal_response.ContentType != dummy_response.ContentType) {
			v.addResult(fmt.Sprintf("Content-Type header differs for %s", URL))
		}
		// if (levenshteinRatio(traversal_response.Body, onestepback_response.Body) < 65) && (levenshteinRatio(traversal_response.Body, v.DummyResponse[c].Body)) < 65 {
		// 	return "Content of the pages differs"
		// }
	}
}


// func (v *SCScanner) printResults(vhost string, size int64, status int) {
// 	v.Printer.PrintRes(vhost, size, status)
// 	v.Printer.PrintProg(v.VHostsNum, v.Scanned)
// 	str := fmt.Sprintf("%s,%d,%d", vhost, size, status)
// 	v.addResult(str)
// }

// func (v *SCScanner) printResultsFuzzy(vhost string, size int64, status int, similarity int) {
// 	v.Printer.PrintResFuzzy(vhost, size, status, similarity)
// 	v.Printer.PrintProg(v.VHostsNum, v.Scanned)
// 	str := fmt.Sprintf("%s,%d,%d,%d", vhost, size, status, similarity)
// 	v.addResult(str)
// }

func (v *SCScanner) Run() {
	threads := v.Opts.Threads
	urls := v.Paths
	payloads := [5]string{"../", "..%2f", "..%2f%26", "..", "..\\"}
	for _,p := range payloads {
		v.Payloads = append(v.Payloads, p)
	}
	// WaitGroup - отслеживает горутины, сколько горутин работает и сколько выполнили свою таску
	var wg sync.WaitGroup
	// создаем канал типом строка c буфером равным количесту тредам, которые мы задали
	urls_to_scan := make(chan string, threads)
	v.setHostnameUrl()
	v.initHttpClient()
	v.WasBanned = false
	v.makeDefaultResponses()
	v.DiffInaRow = 0
	v.ErrorCount = 0
	v.ForbiddenCount = 0
	//v.checkByClientResource(bytes.NewReader(v.RootResponse.Body))
	// запускаем воркеров по количеству тредов
	for i := 0; i < threads; i++ {
		// добавляем в каунтер WaitGroup - увеличиваем на 1 количество горутин каждый раз, когда спавним воркера
		wg.Add(1)
		// спавним горутину (воркера)
		go v.worker(&wg, urls_to_scan)
	}
	// передаем данные для сканирования в канал для выполнения таски воркерами
	for _, url := range urls {
		if len(url) > 0 {
			if url[:1] != "/" {
				url = "/" + url
			}
			if url[len(url)-1:] != "/" {
				url = url + "/"
			}
			urls_to_scan <- url
		}
	}
	if v.Opts.OutputDir != "no.no" {
		v.WriteResults()
	}
	// закрываем vhost channel иначе будет дедлок
	close(urls_to_scan)
	// Ждем пока воркеры закончат таски (пока WaitGroup каунтер будет 0)
	wg.Wait()
}
