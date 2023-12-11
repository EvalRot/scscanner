package main

import (
	"fmt"
	"os"
	"time"
	"pohek/scscanner"
	"github.com/thatisuday/commando"
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
		SetAction(func(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
			basehost := args["basehost"].Value
			wordlist := args["wordlist"].Value
			port, _ := flags["port"].GetInt()
			ssl, _ := flags["ssl"].GetBool()
			followRedirects, _ := flags["followredirects"].GetBool()
			timeout, _ := flags["timeout"].GetInt()
			userAgent, _ := flags["useragent"].GetString()
			threads, _ := flags["threads"].GetInt()
			output, _ := flags["output"].GetString()
			retries, _ := flags["retry"].GetInt()
			insecure, _ := flags["insecure"].GetBool()
			method, _ := flags["method"].GetString()
			urlfile, _ := flags["urlfile"].GetBool()
			proxy, _ := flags["proxy"].GetBool()
			proxyurl, _ := flags["proxy-url"].GetString()
			var sc scscanner.SCScanner
			config := scscanner.NewOptions()
			config.Hostname = basehost
			config.Wordlist = wordlist
			config.Port = port
			config.Ssl = ssl
			config.FollowRedirect = followRedirects
			config.Timeout = time.Duration(timeout) * time.Second
			config.UserAgent = userAgent
			config.Threads = threads
			config.Retry = retries
			config.NoTLSValidation = insecure
			config.Method = method
			config.URLsFile = urlfile
			config.Proxy = proxy
			config.ProxyUrl = proxyurl
			config.OutputDir = output
			sc.Opts = config
			sc.Results = make([]string, 0)
			//sc.Printer = &core.Printer{config}
			//sc.Printer.PrintBanner()
			//sc.Printer.PrintConfig()
			if config.URLsFile {
				err := sc.ReadFileLines()
				if err != nil {
					fmt.Printf("[!] Error opening wordlist file\n")
					os.Exit(0)
				}
				fl, erro := os.Create(output)
				if erro != nil {
					fmt.Printf("[!] Unable to create output directory %s\n", output)
					os.Exit(0)
				}
				fl.Close()
				os.Remove(output)
				sc.Run()
				if output != "no.no" {
					err := sc.WriteResults()
					if err != nil {
						fmt.Printf("\n[!] unable to save results to directory to %s\n", output)
					} else {
						fmt.Printf("\n[+] results saved to directory %s\n", output)
					}
				}
			} else {
				err := sc.ReadFileLines()
				if err != nil {
					fmt.Printf("[!] Error opening wordlist file\n")
					os.Exit(0)
				}
				fl, erro := os.Create(output)
				if erro != nil {
					fmt.Printf("[!] Unable to create directory %s\n", output)
					os.Exit(0)
				}
				fl.Close()
				os.Remove(output)
				sc.Run()
				if output != "no.no" {
					err := sc.WriteResults()
					if err != nil {
						fmt.Printf("\n[!] unable to save results to directory to %s\n", output)
					} else {
						fmt.Printf("\n[+] results saved to directory %s\n", output)
					}
				}
			}
		})
	// commando.
	// 	Register("fuzzy").
	// 	SetDescription("Get Levenshtein distance ratio by comparing Vhosts response body with target. Vhosts can be filtered by specified ratio (if Vhost is similar to target and Levenshtein distance ratio is higher than specified, Vhost will be filtered (not shown)").
	// 	SetShortDescription("Get Levenshtein distance ratio by comparing Vhosts response body with target").
	// 	AddArgument("basehost", "target domain/IP", "").
	// 	AddArgument("wordlist", "path to wordlist", "").
	// 	AddArgument("fuzzytarget", "URL of the target to compare response with with Levenshtein algorithm", "").
	// 	AddFlag("port, p", "target port", commando.Int, 80).
	// 	AddFlag("ratio, r", "Levenshtein distance ratio (similarity ratio). Vhosts will be shown only if ration is below specified", commando.Int, 100).
	// 	AddFlag("ssl", "use ssl", commando.Bool, false).
	// 	AddFlag("sni", "set sni in certificate", commando.Bool, false).
	// 	AddFlag("followredirects", "follow redirects", commando.Bool, false).
	// 	AddFlag("timeout", "request timeout", commando.Int, 5).
	// 	AddFlag("useragent", "set custom useragent", commando.String, "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36").
	// 	AddFlag("threads, t", "number of concurrent threads", commando.Int, 10).
	// 	AddFlag("size", "filter by response size (ignore results with specified size)", commando.Int, -1).
	// 	AddFlag("retry", "max retries", commando.Int, 0).
	// 	AddFlag("output", "path to file to save results", commando.String, "no.no").
	// 	AddFlag("statuscodes", "filter by response code", commando.String, "200,204,301,302,307,401,403").
	// 	AddFlag("ignorestatuscodes", "do not filter responses by status codes", commando.Bool, false).
	// 	AddFlag("proxy", "proxy server (<http://PROXY>)", commando.String, "no.no").
	// 	SetAction(func(args map[string]commando.ArgValue, flags map[string]commando.FlagValue) {
	// 		basehost := args["basehost"].Value
	// 		wordlist := args["wordlist"].Value
	// 		fuzzytarget := args["fuzzytarget"].Value
	// 		ratio, _ := flags["ratio"].GetInt()
	// 		port, _ := flags["port"].GetInt()
	// 		ssl, _ := flags["ssl"].GetBool()
	// 		sni, _ := flags["sni"].GetBool()
	// 		followRedirects, _ := flags["followredirects"].GetBool()
	// 		timeout, _ := flags["timeout"].GetInt()
	// 		userAgent, _ := flags["useragent"].GetString()
	// 		threads, _ := flags["threads"].GetInt()
	// 		size, _ := flags["size"].GetInt()
	// 		statuscodes, _ := flags["statuscodes"].GetString()
	// 		output, _ := flags["output"].GetString()
	// 		ignoreStatus, _ := flags["ignorestatuscodes"].GetBool()
	// 		retries, _ := flags["retry"].GetInt()
	// 		proxy, _ := flags["proxy"].GetString()
	// 		var sc SCScanner
	// 		config := core.NewOptions()
	// 		config.BaseHost = basehost
	// 		config.Wordlist = wordlist
	// 		config.Port = port
	// 		config.Ssl = ssl
	// 		config.Sni = sni
	// 		config.FollowRedirects = followRedirects
	// 		config.Timeout = timeout
	// 		config.UserAgent = userAgent
	// 		config.Threads = threads
	// 		config.Fuzzy = true
	// 		config.FuzzyTarget = fuzzytarget
	// 		config.FuzzyRatio = ratio
	// 		config.IgnoreStatus = ignoreStatus
	// 		config.Retry = retries
	// 		config.Proxy = proxy
	// 		if size != -1 {
	// 			config.CheckSize = true
	// 		} else {
	// 			config.CheckSize = false
	// 		}

	// 		config.Size = int64(size)
	// 		config.StatusCodes = core.StrToInts(statuscodes, ",")
	// 		sc.Opts = config
	// 		sc.Results = make([]string, 0)
	// 		sc.Printer = &core.Printer{config}
	// 		sc.Printer.PrintBanner()
	// 		sc.Printer.PrintConfig()
	// 		err := sc.ReadFileLines()
	// 		if err != nil {
	// 			fmt.Printf("[!] Error opening wordlist file\n")
	// 			os.Exit(0)
	// 		}
	// 		fl, erro := os.Create(output)
	// 		if erro != nil {
	// 			fmt.Printf("[!] Unable to create file %s\n", output)
	// 			os.Exit(0)
	// 		}
	// 		fl.Close()
	// 		os.Remove(output)
	// 		errH := sc.GetModelResponse()
	// 		for i := 0; i <= retries; i++ {
	// 			if errH != nil {
	// 				if i < retries {
	// 					continue
	// 				}
	// 				fmt.Printf("[!] Error connecting to target URL: %v\n", errH)
	// 				os.Exit(0)
	// 			}
	// 			break
	// 		}
	// 		sc.run()
	// 		if output != "no" {
	// 			err := sc.WriteResults(output)
	// 			if err != nil {
	// 				fmt.Printf("\n[!] unable to save results to file to %s\n", output)
	// 			} else {
	// 				fmt.Printf("\n[+] results saved to file %s\n", output)
	// 			}
	// 		}
	// 	})
	commando.Parse(nil)
}
