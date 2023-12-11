package helper

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	Levenshtein "github.com/agnivade/levenshtein"
	"golang.org/x/net/html"
)

func LevenshteinRatio(s1 string, s2 string) int {
	ratio := Levenshtein.ComputeDistance(string(s1), string(s2))
	return ratio
}

func AddTraversal(url string, payloads []string) []string {
	var traversal_urls_list []string
	//short_payloads_list := []string{"../", "..%2f", "..%2f%26", "..", "..\\"}
	for _, payload := range payloads {
		traversal_urls_list = append(traversal_urls_list, url+payload)
	}
	return traversal_urls_list
}



func OneStepBackPath(path string) string {
	if path == "/" {
		return "/"
	}
	if path[len(path)-1:] == "/" {
		path = path[:len(path)-1]
	}
	index := strings.LastIndex(path, "/")
	return path[:index+1]
}

func getHref(t html.Token) (ok bool, href string) {
	// Iterate over all of the Token's attributes until we find an "href"
	for _, a := range t.Attr {
		if a.Key == "href" {
			href = a.Val
			ok = true
		}
		if a.Key == "src" {
			href = a.Val
			ok = true
		}
	}

	// "bare" return will return the variables (ok, href) as defined in
	// the function definition
	return
}

func SplitUrl(parseUrl string, allPaths *[]string) {
	//fmt.Println("try to parse", parseUrl, " URL")
	if parseUrl[len(parseUrl)-1:] != "/" {
		parseUrl += "/"
	}
	u, err := url.Parse(parseUrl)
	if err != nil {
		log.Fatal(err)
	}
	path := u.Path
	tempPath := "/"
	urlParts := strings.Split(path, "/")
	urlParts = urlParts[1:]
	urlParts = urlParts[:len(urlParts)-1]
	for _, v := range urlParts {
		tempPath = tempPath + url.QueryEscape(v) + "/"
		if (len(tempPath) > 0) || (tempPath != "/") {
			*allPaths = append(*allPaths, tempPath)
		}
	}
}

func Unique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func ParseBody(body io.Reader) (path string) {
	var flag bool
	z := html.NewTokenizer(body)
	// reader := bufio.NewReader(os.Stdin)
	for {
		if flag {
			return path
		}
		//fmt.Println("Inside for loop")
		tt := z.Next()
		testt := z.Token()
		//	fmt.Println(testt, " next ", tt)
		switch {
		case tt == html.ErrorToken:
			// End of the document, we're done
			return
		case tt == html.StartTagToken:
			isAnchor := testt.Data == "a" || testt.Data == "link" || testt.Data == "script"

			//fmt.Println(testt.Data, "is anchor", isAnchor)
			if !isAnchor {
				continue
			}

			// Extract the href value, if there is one
			ok, url := getHref(testt)
			if !ok {
				continue
			}
			var text string
			fmt.Println("Type y to use this url for check :", url, "?")
			fmt.Scanln(&text)
			if text == "y" {
				flag = true
				path = url
			}
		}
	}
}
