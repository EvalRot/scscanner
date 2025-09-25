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
	"pohek/internal/modules/crlf"
	"pohek/internal/output"
	"pohek/internal/payload"
)

func main() {
    app := &cli.App{
        Name:    "SCScanner",
        Usage:   "secondary context path traversal scanner",
        Version: "1.1.0",
        ArgsUsage: "<hostname> <url_file>",
        Flags: []cli.Flag{
            &cli.IntFlag{Name: "port", Aliases: []string{"p"}, Value: 443, Usage: "target port for precheck"},
            &cli.BoolFlag{Name: "ssl", Value: true, Usage: "use ssl for precheck base URL"},
            &cli.BoolFlag{Name: "followredirects", Value: false, Usage: "follow redirects"},
            &cli.IntFlag{Name: "timeout", Value: 5, Usage: "request timeout (seconds)"},
            &cli.StringFlag{Name: "method", Value: "GET", Usage: "HTTP method"},
            &cli.BoolFlag{Name: "insecure", Value: true, Usage: "ignore TLS alerts"},
            &cli.StringFlag{Name: "useragent", Value: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36", Usage: "custom user-agent"},
            &cli.IntFlag{Name: "threads", Aliases: []string{"t"}, Value: 15, Usage: "number of concurrent threads (targets)"},
            &cli.IntFlag{Name: "retry", Value: 2, Usage: "max retries per request"},
            &cli.StringFlag{Name: "output", Value: "no.no", Usage: "path to output directory (JSONL) or no.no for stdout"},
            &cli.BoolFlag{Name: "proxy", Value: false, Usage: "use proxy settings from environment (HTTP_PROXY/HTTPS_PROXY)"},
            &cli.StringFlag{Name: "proxy-url", Value: "", Usage: "explicit proxy URL (e.g., http://127.0.0.1:8080)"},
            &cli.BoolFlag{Name: "scpt", Value: true, Usage: "enable Secondary Context Path Traversal module"},
            &cli.BoolFlag{Name: "crlf", Value: false, Usage: "enable CRLF injection module"},
            &cli.BoolFlag{Name: "scpt-precheck", Value: false, Usage: "enable SCPT payload precheck to filter payloads consistently returning 302 (redirect) or 403 (forbidden)"},
            &cli.BoolFlag{Name: "crlf-precheck", Value: false, Usage: "enable CRLF payload precheck to filter payloads consistently returning 403"},
        },
        Action: func(c *cli.Context) error {
            if c.NArg() < 2 {
                return fmt.Errorf("usage: scscanner <hostname> <url_file>")
            }
            basehost := c.Args().Get(0)
            wordlist := c.Args().Get(1)

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
                Proxy:           c.Bool("proxy"),
                ProxyUrl:        c.String("proxy-url"),
                OutputDir:       c.String("output"),
                Headers:         map[string]string{},
            }

            client, err := httpx.New(opt)
            if err != nil {
                return fmt.Errorf("cannot init http client: %w", err)
            }

            var pay *payload.Source // modules will load their own defaults
            sink := output.NewSafe(output.JSONLSink{OutputDir: opt.OutputDir})
            deps := engine.Deps{Opts: opt, Client: client, Payloads: pay, Sink: sink}

            modules := []engine.Module{}
            if c.Bool("scpt") {
                // Optional precheck to filter out payloads that trigger normalization redirects (302)
                // or are blocked by WAF consistently (403)
                if c.Bool("scpt-precheck") {
                    filtered := scpt.RunPrecheck(c.Context, deps)
                    // If precheck removed all payloads or there were none, stop scanning gracefully
                    if filtered == nil || len(filtered) == 0 {
                        fmt.Printf("[scpt-precheck] All payloads were filtered or none available. Stopping scan.\n")
                        return nil
                    }
                    if len(filtered) > 0 {
                        deps.Payloads = payload.NewFrom(filtered)
                    }
                }
                modules = append(modules, scpt.Module{})
            }
            if c.Bool("crlf") {
                if c.Bool("crlf-precheck") {
                    allowed := crlf.RunPrecheck(c.Context, deps)
                    if len(allowed) == 0 {
                        fmt.Printf("[crlf-precheck] All payloads were filtered or none available. Skipping CRLF module.\n")
                    } else {
                        modules = append(modules, crlf.New(allowed))
                    }
                } else {
                    modules = append(modules, crlf.New(nil))
                }
            }
            if len(modules) == 0 {
                return fmt.Errorf("no modules enabled; enable with --scpt or --crlf")
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
