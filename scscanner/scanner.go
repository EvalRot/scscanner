package scscanner

import (
	"bufio"
	"errors"

	//	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"pohek/helper"
	"pohek/printer"
	"strings"
	"sync"
	"time"
)

type SCScanner struct {
	Opts                  *Options
	Paths                 map[string][]string
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
	file, err := os.Open(v.Opts.Wordlist)
	if err != nil {
		return err
	}
	if v.Opts.URLsFile { //using input file with crawled URLs
		defer file.Close()
		v.Paths = make(map[string][]string)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			rawUrl := scanner.Text()
			parsedURL, err := url.Parse(rawUrl)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
				continue
			}
			domain := parsedURL.Scheme + "://" + parsedURL.Host
			path := parsedURL.Path
			v.Paths[domain] = append(v.Paths[domain], path)
		}
		// v.Paths = helper.Unique(v.Paths)
		// v.PathsNum = len(v.Paths)
		return scanner.Err()
	} else {
		defer file.Close()
		v.Paths = make(map[string][]string)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			v.Paths[v.Opts.Hostname] = append(v.Paths[v.Opts.Hostname], scanner.Text())
		}
		// v.PathsNum = len(v.Paths)
		return scanner.Err()
	}

}

func (v *SCScanner) initHttpClient() {
	v.HttpClient, _ = NewHTTPClient(v.Opts)
}

func (v *SCScanner) makeDefaultResponses() error {
	filtered_payloads := []string{}
	filtered_responses := []*Response{}
	dummy_path := "/gachimuchicheburek/"
	r, err := v.HttpClient.CreateResponse(v.HostnameUrl, "")
	if err != nil {
		return errors.New(fmt.Sprintf("Cannot make initial request to %s", v.HostnameUrl))
	}
	v.RootResponse = append(v.RootResponse, r)
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
			return err
		} else {
			filtered_responses = append(filtered_responses, a)
			filtered_payloads = append(filtered_payloads, v.Payloads[i])
		}
	}
	v.DummyResponses = filtered_responses
	v.Payloads = filtered_payloads
	if (len(v.DummyResponses) == 0) || (len(v.Payloads) == 0) {
		fmt.Println("Web app does not allow to use traversal in any way. Program was stopped")
		return errors.New("")
	}
	return nil
}

func (v *SCScanner) worker(wg *sync.WaitGroup, urls_to_scan <-chan string) {
	// Уменьшаем контер горутин, когда выполнена таска
	defer wg.Done()
	//for loop используем чтобы читать данные из канала, когда их много
	for u := range urls_to_scan {
		u, _ := url.Parse(u)
		path := u.Path
		var onestepback_response, dummy_response *Response
		onestepback_path := helper.OneStepBackPath(path)
		dummy_path := onestepback_path + "gachimuchicheburek/"
		nonexistent_path := path + "gachimuchicheburek/"
		nonexistent_response, err := v.HttpClient.CreateResponse(v.HostnameUrl, nonexistent_path)
		if err != nil {
			fmt.Println("URL ", v.HostnameUrl, nonexistent_path, " does not respond. Skipping")
			continue
		}
		//fmt.Println("Path is ", path, "back path is ", onestepback_path, "dummy_path is ", dummy_path)
		if (onestepback_path == "/") || (onestepback_path == " ") || (len(onestepback_path) == 0) {
			onestepback_response = v.RootResponse[0]
		} else {
			onestepback_response, err = v.HttpClient.CreateResponse(v.HostnameUrl, onestepback_path)
			if err != nil {
				fmt.Println("URL ", v.HostnameUrl, onestepback_path, " does not respond. Skipping")
				continue
			}
		}
		retries := v.Opts.Retry
		traversal_paths := helper.AddTraversal(path, v.Payloads)
		traversal_dummy_paths := helper.AddTraversal(dummy_path, v.Payloads)
	OuterLoop:
		for c, url := range traversal_paths {
			if !v.Opts.URLsFile {
				dummy_response = v.DummyResponses[c]
			} else {
				dummy_response, err = v.HttpClient.CreateResponse(v.HostnameUrl, traversal_dummy_paths[c])
				if err != nil {
					fmt.Println("URL ", v.HostnameUrl, onestepback_path, " does not respond. Skipping")
					continue
				}
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
						fmt.Println("Web app ", v.HostnameUrl, " responds with 5 errors in a row. Skip this host")
						break OuterLoop
					} else {
						v.Printer.PrintErr(v.HostnameUrl+url, err)
						str := v.HostnameUrl + url
						v.addResult(str)
						rand.Seed(time.Now().UnixNano())
						min := 2
						max := 5
						n := rand.Intn(max-min+1) + min
						time.Sleep(time.Duration(n) * time.Second)
						v.mu.Unlock()
						break
					}

				} else {
					v.ErrorCount = 0
					v.findDifference(resp, url, onestepback_response, dummy_response, nonexistent_response)
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
	}
}

func (v *SCScanner) findDifference(traversal_response *Response, URL string, onestepback_response *Response, dummy_response *Response, nonexistent_response *Response) {
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
		if (traversal_response.StatusCode != onestepback_response.StatusCode) && (traversal_response.StatusCode != dummy_response.StatusCode) && (traversal_response.StatusCode != nonexistent_response.StatusCode) {
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
			v.addResult(fmt.Sprintf("Status code differs for %s. Traversal: %d, OneStepBack: %d, Dummy: %d,", URL, traversal_response.StatusCode, onestepback_response.StatusCode, dummy_response.StatusCode))
			v.DiffInaRow++
		}
		if (traversal_response.Server != onestepback_response.Server) && (traversal_response.Server != dummy_response.Server) && (traversal_response.Server != nonexistent_response.Server) {
			//fmt.Println(string(traversal_response.Body))
			v.addResult(fmt.Sprintf("Server header differs for %s", URL))
			v.DiffInaRow++
		}
		if (traversal_response.ContentType != onestepback_response.ContentType) && (traversal_response.ContentType != dummy_response.ContentType) && (traversal_response.ContentType != nonexistent_response.ContentType) {
			//fmt.Println(string(traversal_response.Body))
			v.addResult(fmt.Sprintf("Content-Type header differs for %s", URL))
			v.DiffInaRow++
		}
		// if (levenshteinRatio(traversal_response.Body, onestepback_response.Body) < 65) && (levenshteinRatio(traversal_response.Body, v.DummyResponse[c].Body)) < 65 {
		// 	return "Content of the pages differs"
		// }
	} else {
		if (traversal_response.StatusCode != onestepback_response.StatusCode) && (traversal_response.StatusCode != dummy_response.StatusCode) && (traversal_response.StatusCode != nonexistent_response.StatusCode) {
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
			//fmt.Println(traversal_response.Request.URL, onestepback_response.Request.URL, dummy_response.Request.URL)
			v.addResult(fmt.Sprintf("Status code differs for %s", URL))
		}
		// if (traversal_response.Server != onestepback_response.Server) && (traversal_response.Server != dummy_response.Server) {
		// 	v.addResult(fmt.Sprintf("Server header differs for %s", URL))
		// }
		if (traversal_response.ContentType != onestepback_response.ContentType) && (traversal_response.ContentType != dummy_response.ContentType) && (traversal_response.ContentType != nonexistent_response.ContentType) {
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
	payloads := [5]string{"../", "..%2f", "..%2f%26", "..", "..\\"}
	v.PathsNum = len(v.Paths)
	for domain, paths := range v.Paths {
		v.Scanned++
		v.HostnameUrl = domain
		v.Printer.PrintProg(v.PathsNum, v.Scanned)
		fmt.Println("Running scan for ", domain, " domain. ", len(paths), " pathes to scan")
		for _, p := range payloads {
			v.Payloads = append(v.Payloads, p)
		}
		// WaitGroup - отслеживает горутины, сколько горутин работает и сколько выполнили свою таску
		var wg sync.WaitGroup
		// создаем канал типом строка c буфером равным количесту тредам, которые мы задали
		urls_to_scan := make(chan string, threads)
		// v.setHostnameUrl(domain)
		v.initHttpClient()
		v.WasBanned = false
		err := v.makeDefaultResponses()
		if err != nil {
			fmt.Println(err)
			continue
		}
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
		for _, url := range paths {
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
}
