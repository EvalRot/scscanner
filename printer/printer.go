package printer

import (
	"fmt"
	"os"
)

const (
	CR      = "\r\x1b[2K"
	RED     = "\x1b[31m"
	NOCOLOR = "\x1b[0m"
)

type Printer struct {
	//	Opts *Options
}

func (p *Printer) PrintBanner() {

	banner := `
  ____    __     ___   _           _       
 / ___| __\ \   / / | | | ___  ___| |_ ___ 
| |  _ / _ \ \ / /| |_| |/ _ \/ __| __/ __|
| |_| | (_) \ V / |  _  | (_) \__ \ |_\__ \
 \____|\___/ \_/  |_| |_|\___/|___/\__|___/										  
___________________________________________	
 `
	fmt.Println(banner)
}

// func (p *Printer) PrintConfig() {
// 	fmt.Printf(":: Target: %v\n", p.Opts.Hostname)
// 	//fmt.Printf(":: Port: %d\n", p.Opts.Port)
// 	fmt.Printf(":: Follow redirects: %v\n", p.Opts.FollowRedirect)
// 	fmt.Printf(":: Timeout: %d\n", p.Opts.Timeout)
// 	fmt.Printf(":: Threads: %d\n", p.Opts.Threads)
// 	//fmt.Printf(":: SSL: %v\n", p.Opts.Ssl)
// 	//fmt.Printf(":: SNI: %v\n", p.Opts.Ssl)
// 	// if !p.Opts.IgnoreStatus {
// 	// 	fmt.Printf(":: Status codes: %v\n", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(p.Opts.StatusCodes)), ","), "[]"))
// 	// }
// 	// if p.Opts.CheckSize {
// 	// 	fmt.Printf(":: Size: %v\n", p.Opts.Size)
// 	// }
// 	// if p.Opts.Fuzzy {
// 	// 	fmt.Printf(":: Similarity ratio: %v%%\n", p.Opts.FuzzyRatio)
// 	// }
// 	fmt.Printf("___________________________________________\n")
// }

func (p *Printer) PrintProg(vhostsNum int, scanned int) {
	fmt.Fprintf(os.Stderr, "%sProgress: [%d/%d] \n", CR, scanned, vhostsNum)
}

func (p *Printer) PrintRes(vhost string, size int64, status int) {
	res := fmt.Sprintf("%s%-23s [Status: %d, Size: %d]", CR, vhost, status, size)
	fmt.Println(res)
}

func (p *Printer) PrintResFuzzy(vhost string, size int64, status int, ratio int) {
	res := fmt.Sprintf("%s%-23s [Status: %d, Size: %d, similarity: %d%%]", CR, vhost, status, size, ratio)
	fmt.Println(res)
}

func (p *Printer) PrintErr(vhost string, err error) {
	res := fmt.Sprintf("%s%-23s [error: %s%v%s]", CR, vhost, RED, err, NOCOLOR)
	fmt.Println(res)
}
