package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/urfave/cli/v2"

    // Internal layered packages
    "pohek/internal/config"
    "pohek/internal/engine"
    "pohek/internal/httpx"
    "pohek/internal/modules/scpt"
    "pohek/internal/output"
    "pohek/internal/payload"
)

func main() {
    app := &cli.App{
        Name:    "SCScanner",
        Usage:   "secondary context path traversal scanner",
        Version: "1.0.0",
        Flags: []cli.Flag{
            &cli.StringFlag{Name: "basehost", Usage: "target domain/IP (ignored with --urlfile)", Required: false},
            &cli.StringFlag{Name: "wordlist", Usage: "path to wordlist or URLs file", Required: true},
            &cli.IntFlag{Name: "port", Aliases: []string{"p"}, Value: 443, Usage: "target port"},
            &cli.BoolFlag{Name: "ssl", Value: false, Usage: "use ssl"},
            &cli.BoolFlag{Name: "urlfile", Value: false, Usage: "treat wordlist as a file with absolute URLs"},
            &cli.BoolFlag{Name: "followredirects", Value: false, Usage: "follow redirects"},
            &cli.IntFlag{Name: "timeout", Value: 5, Usage: "request timeout (seconds)"},
            &cli.StringFlag{Name: "method", Value: "GET", Usage: "HTTP method"},
            &cli.BoolFlag{Name: "insecure", Value: true, Usage: "ignore TLS alerts"},
            &cli.StringFlag{Name: "useragent", Value: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36", Usage: "custom user-agent"},
            &cli.IntFlag{Name: "threads", Aliases: []string{"t"}, Value: 15, Usage: "number of concurrent threads (targets)"},
            &cli.IntFlag{Name: "retry", Value: 1, Usage: "max retries per request"},
            &cli.StringFlag{Name: "output", Value: "no.no", Usage: "path to output directory (JSONL) or no.no for stdout"},
            &cli.BoolFlag{Name: "proxy", Value: false, Usage: "use proxy settings from environment (HTTP_PROXY/HTTPS_PROXY)"},
            &cli.StringFlag{Name: "proxy-url", Value: "", Usage: "explicit proxy URL (e.g., http://127.0.0.1:8080)"},
            &cli.BoolFlag{Name: "scpt", Value: true, Usage: "enable Secondary Context Path Traversal module"},
        },
        Action: func(c *cli.Context) error {
            basehost := c.String("basehost")
            wordlist := c.String("wordlist")
            if wordlist == "" {
                return fmt.Errorf("wordlist is required")
            }

            opt := &config.Options{
                Hostname:        basehost,
                Wordlist:        wordlist,
                Port:            c.Int("port"),
                Ssl:             c.Bool("ssl"),
                FollowRedirect:  c.Bool("followredirects"),
                Timeout:         time.Duration(c.Int("timeout")) * time.Second,
                UserAgent:       c.String("useragent"),
                Threads:         c.Int("threads"),
                Retry:           c.Int("retry"),
                NoTLSValidation: c.Bool("insecure"),
                Method:          c.String("method"),
                URLsFile:        c.Bool("urlfile"),
                Proxy:           c.Bool("proxy"),
                ProxyUrl:        c.String("proxy-url"),
                OutputDir:       c.String("output"),
                Headers:         map[string]string{},
            }

            client, err := httpx.New(opt)
            if err != nil {
                return fmt.Errorf("cannot init http client: %w", err)
            }

            pay := payload.NewDefault()
            sink := output.NewSafe(output.JSONLSink{OutputDir: opt.OutputDir})
            deps := engine.Deps{Opts: opt, Client: client, Payloads: pay, Sink: sink}

            modules := []engine.Module{}
            if c.Bool("scpt") {
                modules = append(modules, scpt.Module{})
            }
            if len(modules) == 0 {
                return fmt.Errorf("no modules enabled; enable with --scpt")
            }

            eng := &engine.Engine{Deps: deps, Modules: modules}
            ctx := context.Background()
            if err := eng.Run(ctx); err != nil {
                return err
            }
            return nil
        },
    }

    if err := app.Run(os.Args); err != nil {
        fmt.Fprintf(os.Stderr, "[!] %v\n", err)
        os.Exit(1)
    }
}
