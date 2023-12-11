package scscanner

import "time"

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
	Headers         []HTTPHeader
	Cookies         string
	URLsFile        bool
	Proxy           bool
	ProxyUrl        string
	OutputDir       string
}

func NewOptions() *Options {
	return &Options{}
}
