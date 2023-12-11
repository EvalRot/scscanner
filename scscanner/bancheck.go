package scscanner

import (
	"fmt"
    "strings"
	"time"
	"os"
)

func (v *SCScanner) CheckForBanTemplate (resp *Response) {
	conditions := []func(resp *Response) bool{
		func (resp *Response) bool {
			if (resp.StatusCode == 503) && (strings.Contains(string(resp.Body), "Guru meditation:")) {
				fmt.Println("You have been banned by Qrator")
				return true
			} else {
				return false
			}
		},
	}

	for _, cond := range conditions {
		if cond(resp) {
			v.ForbiddenCount = 0
			v.WasBanned = true
			fmt.Println("The program is paused for 1 minute and then continue with delay between requests")
			v.HttpClient.AddDelay()
			pause := 60 * time.Second
			time.Sleep(pause)
		}
	}
}

func (v *SCScanner) checkForBan (resp *Response) {
	if (resp.StatusCode == 403) || (resp.StatusCode == 429) || (resp.StatusCode == 503) || (resp.StatusCode == 502){
		v.ForbiddenCount++
		if v.ForbiddenCount > 9 {
			if v.WasBanned {
				fmt.Println("Adding delay to requests did not help. The program was stopped")
				os.Exit(3)
			}
			resp, _ := v.HttpClient.CreateResponse(v.HostnameUrl, "")
			if resp.StatusCode != v.RootResponse[0].StatusCode {
				v.ForbiddenCount = 0
				v.WasBanned = true
				fmt.Println("Web app responds with errors. You have been banned probably. The program is paused for 1 minute and then continue with delay between requests")
				v.HttpClient.AddDelay()
				pause := 60 * time.Second
				time.Sleep(pause)
			}
		} else if v.ForbiddenCount > 4 {
			v.CheckForBanTemplate(resp)
		}
	} 
}