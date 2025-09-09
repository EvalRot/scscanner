package scscanner

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type Response struct {
	Server      string
	ContentType string
	StatusCode  int
	Body        []byte
	Request     *http.Request
}

type HttpErr struct {
	err error
}

type HTTPHeader struct {
	Name  string
	Value string
}

type HTTPClient struct {
	client    *http.Client
	userAgent string
	headers   []HTTPHeader
	cookies   string
	method    string
	delay     bool
}

func NewHTTPClient(opt *Options) (*HTTPClient, error) {
	var client HTTPClient
	client.delay = false
	proxyURL := http.ProxyFromEnvironment
	if opt == nil {
		return nil, fmt.Errorf("options is nil")
	}

	if opt.Proxy {
		pu, _ := url.Parse(opt.ProxyUrl)
		proxyURL = http.ProxyURL(pu)
		fmt.Println(proxyURL)
	}

	var redirectFunc func(req *http.Request, via []*http.Request) error
	if !opt.FollowRedirect {
		redirectFunc = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		redirectFunc = nil
	}
	customtransport := http.DefaultTransport.(*http.Transport).Clone()
	customtransport.MaxIdleConns = 100
	customtransport.MaxConnsPerHost = 100
	customtransport.MaxIdleConnsPerHost = 100
	customtransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	if opt.Proxy {
		customtransport.Proxy = proxyURL
	}

	client.client = &http.Client{
		Timeout:       opt.Timeout,
		CheckRedirect: redirectFunc,
		Transport:     customtransport,
	}

	client.userAgent = opt.UserAgent
	client.headers = opt.Headers
	client.cookies = opt.Cookies
	client.method = opt.Method
	if client.method == "" {
		client.method = http.MethodGet
	}
	return &client, nil
}

func (client *HTTPClient) SetRedirects(flag bool) {
	var redirectFunc func(req *http.Request, via []*http.Request) error
	if !flag {
		redirectFunc = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		redirectFunc = nil
	}
	client.client.CheckRedirect = redirectFunc
}

func (client *HTTPClient) AddDelay() {
	if !client.delay {
		client.delay = true
	}

}

func (client *HTTPClient) CreateResponse(hostname string, urlPath string) (*Response, error) {
	req, err := http.NewRequest(client.method, hostname, nil)
	if err != nil {
		return nil, err
	}
	req.URL.Opaque = urlPath
	if client.cookies != "" {
		req.Header.Set("Cookie", client.cookies)
	}

	if client.userAgent != "" {
		req.Header.Set("User-Agent", client.userAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0")
	}

	// add custom headers
	for _, h := range client.headers {
		req.Header.Set(h.Name, h.Value)
	}

	resp, err := client.client.Do(req)
	if err != nil {

		return &Response{}, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var target_response Response
	target_response.Server = resp.Header.Get("Server")
	target_response.ContentType = resp.Header.Get("Content-Type")
	target_response.StatusCode = resp.StatusCode
	target_response.Body = body
	target_response.Request = resp.Request
	if client.delay {
		delay := 1 * time.Second
		time.Sleep(delay)
	}
	return &target_response, err
}
