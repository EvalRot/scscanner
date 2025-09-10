package httpx

import (
    "crypto/tls"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "time"

    "pohek/internal/config"
)

// Response is a minimal, serializable representation of an HTTP response
// used by scanner and detectors. It intentionally avoids exposing net/http internals.
type Response struct {
    Server      string
    ContentType string
    StatusCode  int
    Body        []byte
    RequestURL  string
}

// Client wraps net/http.Client and request building logic (headers, cookies, method, redirects, TLS).
// It also supports raw path injection using Request.URL.Opaque for traversal testing.
type Client struct {
    hc        *http.Client
    userAgent string
    headers   map[string]string
    cookies   string
    method    string
    delay     bool
}

// New creates a new HTTP client from config.Options.
func New(opt *config.Options) (*Client, error) {
    if opt == nil {
        return nil, fmt.Errorf("options is nil")
    }

    proxyFunc := http.ProxyFromEnvironment
    if opt.Proxy {
        if opt.ProxyUrl != "" {
            pu, err := url.Parse(opt.ProxyUrl)
            if err == nil {
                proxyFunc = http.ProxyURL(pu)
            }
        }
    }

    // Configure redirect policy
    var redirectFunc func(req *http.Request, via []*http.Request) error
    if !opt.FollowRedirect {
        redirectFunc = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
    }

    // Clone default transport and adjust knobs
    tr := http.DefaultTransport.(*http.Transport).Clone()
    tr.MaxIdleConns = 100
    tr.MaxConnsPerHost = 100
    tr.MaxIdleConnsPerHost = 100
    tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: opt.NoTLSValidation}
    tr.Proxy = proxyFunc

    c := &Client{
        hc: &http.Client{
            Timeout:       opt.Timeout,
            CheckRedirect: redirectFunc,
            Transport:     tr,
        },
        userAgent: opt.UserAgent,
        headers:   opt.Headers,
        cookies:   opt.Cookies,
        method:    opt.Method,
    }
    if c.method == "" {
        c.method = http.MethodGet
    }
    return c, nil
}

// SetRedirects toggles following redirects at runtime.
func (c *Client) SetRedirects(follow bool) {
    var redirectFunc func(req *http.Request, via []*http.Request) error
    if !follow {
        redirectFunc = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
    }
    c.hc.CheckRedirect = redirectFunc
}

// AddDelay enables small delays between requests (used by anti-ban strategies).
func (c *Client) AddDelay() { c.delay = true }

// Do issues a request to baseURL with the provided raw path inserted as Request.URL.Opaque.
// baseURL must be a valid absolute URL without a path (scheme://host[:port]).
func (c *Client) Do(baseURL string, rawPath string) (*Response, error) {
    req, err := http.NewRequest(c.method, baseURL, nil)
    if err != nil {
        return nil, err
    }
    // Use opaque to avoid path normalization. Keep raw traversal sequences intact.
    req.URL.Opaque = rawPath

    if c.cookies != "" {
        req.Header.Set("Cookie", c.cookies)
    }
    if c.userAgent != "" {
        req.Header.Set("User-Agent", c.userAgent)
    } else {
        req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/78.0")
    }
    for k, v := range c.headers {
        req.Header.Set(k, v)
    }

    resp, err := c.hc.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)

    out := &Response{
        Server:      resp.Header.Get("Server"),
        ContentType: resp.Header.Get("Content-Type"),
        StatusCode:  resp.StatusCode,
        Body:        body,
        RequestURL:  resp.Request.URL.String(),
    }
    if c.delay {
        time.Sleep(1 * time.Second)
    }
    return out, nil
}

