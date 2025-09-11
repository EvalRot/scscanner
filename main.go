package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/thatisuday/commando"

    // Internal layered packages
    "pohek/internal/config"
    "pohek/internal/engine"
    "pohek/internal/httpx"
    "pohek/internal/modules/scpt"
    "pohek/internal/output"
    "pohek/internal/payload"
)

func main() {
	commando.
		SetExecutableName("SCScanner").
		SetVersion("1.0.0").
		SetDescription("secondary context path traversal scanner")
	commando.
		Register(nil).
		AddArgument("basehost", "target domain/IP", "").
		AddArgument("wordlist", "path to wordlist", "").
		AddFlag("port, p", "target port", commando.Int, 443).
		AddFlag("ssl", "use ssl", commando.Bool, false).
		AddFlag("urlfile", "file with URLs to test", commando.Bool, false).
		AddFlag("followredirects", "follow redirects", commando.Bool, false).
		AddFlag("timeout", "request timeout", commando.Int, 5).
		AddFlag("method", "HTTP method", commando.String, "GET").
		AddFlag("insecure", "Ignore TLS alerts", commando.Bool, true).
		AddFlag("useragent", "set custom useragent", commando.String, "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36").
		AddFlag("threads, t", "number of concurrent threads", commando.Int, 15).
		AddFlag("retry", "max retries", commando.Int, 1).
		AddFlag("output", "path to output directory", commando.String, "no.no").
		AddFlag("proxy", "proxy server from env variable", commando.Bool, nil).
		AddFlag("proxy-url", "proxy server from env variable", commando.String, "proxy").
		AddFlag("scpt", "enable Secondary Context Path Traversal module", commando.Bool, true).
        SetAction(func(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
            // Gather CLI values
            basehost := args["basehost"].Value
            wordlist := args["wordlist"].Value
            port, _ := flags["port"].GetInt()
            ssl, _ := flags["ssl"].GetBool()
            followRedirects, _ := flags["followredirects"].GetBool()
            timeout, _ := flags["timeout"].GetInt()
            userAgent, _ := flags["useragent"].GetString()
            threads, _ := flags["threads"].GetInt()
            outdir, _ := flags["output"].GetString()
            retries, _ := flags["retry"].GetInt()
            insecure, _ := flags["insecure"].GetBool()
            method, _ := flags["method"].GetString()
            urlfile, _ := flags["urlfile"].GetBool()
            proxy, _ := flags["proxy"].GetBool()
            proxyurl, _ := flags["proxy-url"].GetString()

            // Build options
            opt := &config.Options{
                Hostname:        basehost,
                Wordlist:        wordlist,
                Port:            port,
                Ssl:             ssl,
                FollowRedirect:  followRedirects,
                Timeout:         time.Duration(timeout) * time.Second,
                UserAgent:       userAgent,
                Threads:         threads,
                Retry:           retries,
                NoTLSValidation: insecure,
                Method:          method,
                URLsFile:        urlfile,
                Proxy:           proxy,
                ProxyUrl:        proxyurl,
                OutputDir:       outdir,
                Headers:         map[string]string{},
            }

            // Build dependencies for the layered scanner
            client, err := httpx.New(opt)
            if err != nil {
                fmt.Printf("[!] cannot init http client: %v\n", err)
                os.Exit(1)
            }
            pay := payload.NewDefault()
            sink := output.NewSafe(output.JSONLSink{OutputDir: opt.OutputDir})

            // Prepare engine with modules controlled by CLI flags
            deps := engine.Deps{Opts: opt, Client: client, Payloads: pay, Sink: sink}
            modules := []engine.Module{}
            scptEnabled, _ := flags["scpt"].GetBool()
            if scptEnabled {
                modules = append(modules, scpt.Module{})
            }
            if len(modules) == 0 {
                fmt.Println("[!] no modules enabled; enable with --scpt")
                os.Exit(1)
            }
            eng := &engine.Engine{Deps: deps, Modules: modules}


            // Run with a cancellable context to enable future graceful shutdowns
            ctx := context.Background()
            if err := eng.Run(ctx); err != nil {
                fmt.Printf("[!] run error: %v\n", err)
                os.Exit(1)
            }
        })
		
	commando.Parse(nil)
}
