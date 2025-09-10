package config

import (
    "fmt"
    "net/url"
    "time"
)

// Options holds all runtime configuration for the scanner.
// It is intentionally decoupled from CLI to keep core logic testable and reusable.
type Options struct {
    Hostname        string
    Port            int
    Ssl             bool
    Method          string
    FollowRedirect  bool
    Timeout         time.Duration
    Wordlist        string
    UserAgent       string
    Threads         int
    NoTLSValidation bool
    Retry           int
    Headers         map[string]string
    Cookies         string
    URLsFile        bool
    Proxy           bool
    ProxyUrl        string
    OutputDir       string
}

// BuildBaseURL constructs scheme://host[:port] from Options.
// It does not append any path – paths are supplied separately per request.
func (o *Options) BuildBaseURL() (string, error) {
    if o.Hostname == "" {
        return "", fmt.Errorf("hostname is empty")
    }
    scheme := "http"
    if o.Ssl {
        scheme = "https"
    }
    host := o.Hostname
    // Only append port if it is non-standard for the chosen scheme
    if (o.Port > 0) && !((!o.Ssl && o.Port == 80) || (o.Ssl && o.Port == 443)) {
        host = fmt.Sprintf("%s:%d", host, o.Port)
    }

    u := url.URL{Scheme: scheme, Host: host}
    return u.String(), nil
}

