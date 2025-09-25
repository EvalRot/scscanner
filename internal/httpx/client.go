package httpx

import (
    "crypto/tls"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "strconv"
    "sync"
    "sync/atomic"
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
    RetryAfter  time.Duration
    Headers     http.Header
}

// Client wraps net/http.Client and request building logic (headers, cookies, method, redirects, TLS).
// It also supports raw path injection using Request.URL.Opaque for traversal testing.
type Client struct {
    hc        *http.Client
    userAgent string
    headers   map[string]string
    cookies   string
    method    string
    // Adaptive global pacing between requests across all workers, in milliseconds.
    delayMs   int64 // accessed atomically
    // 429 tracking to escalate delay from 0 -> 500ms -> 1000ms
    mu            sync.Mutex
    delayPhase    int       // 0: none, 1: 500ms, 2: 1000ms
    delaySince    time.Time // time when current delayPhase became active
}

// New creates a new HTTP client from config.Options.
func New(opt *config.Options) (*Client, error) {
    if opt == nil {
        return nil, fmt.Errorf("options is nil")
    }

    // Configure proxy selection
    // Priority:
    // 1) Explicit ProxyUrl if provided and valid
    // 2) Environment proxies if --proxy is set
    // 3) No proxy otherwise
    var proxyFunc func(*http.Request) (*url.URL, error)
    if opt.ProxyUrl != "" {
        if pu, err := url.Parse(opt.ProxyUrl); err == nil && pu.Scheme != "" && pu.Host != "" {
            proxyFunc = http.ProxyURL(pu)
        } else {
            // Invalid proxy URL provided; fall back based on --proxy flag
            if opt.Proxy {
                proxyFunc = http.ProxyFromEnvironment
            } else {
                proxyFunc = nil
            }
        }
    } else if opt.Proxy {
        proxyFunc = http.ProxyFromEnvironment
    } else {
        proxyFunc = nil
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

// setGlobalDelay safely updates the inter-request delay and marks when it became active.
func (c *Client) setGlobalDelay(d time.Duration, activatedAt time.Time, phase int) {
    atomic.StoreInt64(&c.delayMs, d.Milliseconds())
    c.delayPhase = phase
    c.delaySince = activatedAt
}

// maybeEscalateDelayOn429 escalates delay: none -> 500ms, then -> 1000ms.
// The second escalation only triggers for requests sent after the first delay became active.
func (c *Client) maybeEscalateDelayOn429(reqStarted time.Time) {
    c.mu.Lock()
    defer c.mu.Unlock()
    switch c.delayPhase {
    case 0:
        c.setGlobalDelay(500*time.Millisecond, reqStarted, 1)
    case 1:
        if reqStarted.After(c.delaySince) {
            c.setGlobalDelay(1000*time.Millisecond, reqStarted, 2)
        }
    }
}

// Do issues a request to baseURL with the provided raw path inserted as Request.URL.Opaque.
// baseURL must be a valid absolute URL without a path (scheme://host[:port]).
func (c *Client) Do(baseURL string, rawPath string) (*Response, error) {
    // Apply current pacing before issuing the request to ensure delay affects subsequent traffic.
    if dms := atomic.LoadInt64(&c.delayMs); dms > 0 {
        time.Sleep(time.Duration(dms) * time.Millisecond)
    }

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

    // Record when the request is sent to evaluate 429 escalation boundaries.
    started := time.Now()
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
        Headers:     resp.Header.Clone(),
    }
    // Capture Retry-After if present
    if ra := resp.Header.Get("Retry-After"); ra != "" {
        if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
            out.RetryAfter = time.Duration(secs) * time.Second
        } else if t, err := http.ParseTime(ra); err == nil {
            if dur := time.Until(t); dur > 0 { out.RetryAfter = dur }
        }
    }
    // Escalate global delay on 429 according to policy
    if resp.StatusCode == http.StatusTooManyRequests { // 429
        c.maybeEscalateDelayOn429(started)
    }
    return out, nil
}
