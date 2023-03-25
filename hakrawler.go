package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

type Result struct {
	Source string
	URL    string
	Where  string
}

var headers map[string]string

// Thread safe map
var sm sync.Map
var inputnames []string
func main() {
	inside := flag.Bool("i", false, "Only crawl inside path")
	threads := flag.Int("t", 8, "Number of threads to utilise.")
	depth := flag.Int("d", 2, "Depth to crawl.")
	maxSize := flag.Int("size", -1, "Page size limit, in KB.")
	insecure := flag.Bool("insecure", false, "Disable TLS verification.")
	subsInScope := flag.Bool("subs", false, "Include subdomains for crawling.")
	showJson := flag.Bool("json", false, "Output as JSON.")
	showSource := flag.Bool("s", false, "Show the source of URL based on where it was found. E.g. href, form, script, etc.")
	showWhere := flag.Bool("w", false, "Show at which link the URL is found.")
	rawHeaders := flag.String(("h"), "", "Custom headers separated by two semi-colons. E.g. -h \"Cookie: foo=bar;;Referer: http://example.com/\" ")
	unique := flag.Bool(("u"), false, "Show only unique urls.")
	proxy := flag.String(("proxy"), "", "Proxy URL. E.g. -proxy http://127.0.0.1:8080")
	timeout := flag.Int("timeout", -1, "Maximum time to crawl each URL from stdin, in seconds.")
	disableRedirects := flag.Bool("dr", false, "Disable following HTTP redirects.   \n \n The wordlist of parameter names is @ /user/home/YOU/list/hakrawler_parameters.txt")
	flag.Parse()

	if *proxy != "" {
		os.Setenv("PROXY", *proxy)
	}
	proxyURL, _ := url.Parse(os.Getenv("PROXY"))

	// Convert the headers input to a usable map (or die trying)
	err := parseHeaders(*rawHeaders)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing headers:", err)
		os.Exit(1)
	}

	// Check for stdin input
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No urls detected. Hint: cat urls.txt | hakrawler")
		os.Exit(1)
	}

	results := make(chan string, *threads)
	go func() {
		// get each line of stdin, push it to the work channel
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			url := s.Text()
			hostname, err := extractHostname(url)
			if err != nil {
				log.Println("Error parsing URL:", err)
				continue
			}

			allowed_domains := []string{hostname}
			// if "Host" header is set, append it to allowed domains
			if headers != nil {
				if val, ok := headers["Host"]; ok {
					allowed_domains = append(allowed_domains, val)
				}
			}

			// Instantiate default collector
			c := colly.NewCollector(
				// default user agent header
				colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
				// set custom headers
				colly.Headers(headers),
				// limit crawling to the domain of the specified URL
				colly.AllowedDomains(allowed_domains...),
				// set MaxDepth to the specified depth
				colly.MaxDepth(*depth),
				// specify Async for threading
				colly.Async(true),
			)

			// set a page size limit
			if *maxSize != -1 {
				c.MaxBodySize = *maxSize * 1024
			}

			// if -subs is present, use regex to filter out subdomains in scope.
			if *subsInScope {
				c.AllowedDomains = nil
				c.URLFilters = []*regexp.Regexp{regexp.MustCompile(".*(\\.|\\/\\/)" + strings.ReplaceAll(hostname, ".", "\\.") + "((#|\\/|\\?).*)?")}
			}

			// If `-dr` flag provided, do not follow HTTP redirects.
			if *disableRedirects {
				c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				})
			}
			// Set parallelism
			c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: *threads})

			// Print every href found, and visit it
			c.OnHTML("a[href]", func(e *colly.HTMLElement) {
				link := e.Attr("href")
				abs_link := e.Request.AbsoluteURL(link)
				if strings.Contains(abs_link, url) || !*inside {

					printResult(link, "href", *showSource, *showWhere, *showJson, results, e)
					e.Request.Visit(link)
				}
			})

			// find and print all the JavaScript files
			c.OnHTML("script[src]", func(e *colly.HTMLElement) {
				printResult(e.Attr("src"), "script", *showSource, *showWhere, *showJson, results, e)
			})

			// find and print all the form action URLs
			c.OnHTML("form[action]", func(e *colly.HTMLElement) {
				printResult(e.Attr("action"), "form", *showSource, *showWhere, *showJson, results, e)
			})

                        c.OnHTML("input[name]", func(e *colly.HTMLElement) {

var inputname string 
inputname =  "?&"+e.Attr("name")
                                printResult(inputname, "input", *showSource, *showWhere, *showJson, results, e)
 inputnames = append(inputnames , e.Attr("name"))                      
//fmt.Println(inputnames) 
writewordlist(e.Attr("name"))
})







/* file, err := os.OpenFile("output.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
var i int

    // Append data to the file
    if _, err := file.WriteString(inputnames[i]); err != nil {
i+=1
        log.Fatal(err)
    }
*/
    // Confirm that data was written to the file


                    //    inputnames = append(e.Attr("name")
//fmt.Println(inputnames)
			// add the custom headers
			if headers != nil {
				c.OnRequest(func(r *colly.Request) {
					for header, value := range headers {
						r.Headers.Set(header, value)
					}
				})
			}

			if *proxy != "" {
				// Skip TLS verification for proxy, if -insecure specified
				c.WithTransport(&http.Transport{
					Proxy:           http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
				})
			} else {
				// Skip TLS verification if -insecure flag is present
				c.WithTransport(&http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
				})
			}

			if *timeout == -1 {
				// Start scraping
				c.Visit(url)
				// Wait until threads are finished
				c.Wait()
			} else {
				finished := make(chan int, 1)

				go func() {
					// Start scraping
					c.Visit(url)
					// Wait until threads are finished
					c.Wait()
					finished <- 0
				}()

				select {
				case _ = <-finished: // the crawling finished before the timeout
					close(finished)
					continue
				case <-time.After(time.Duration(*timeout) * time.Second): // timeout reached
					log.Println("[timeout] " + url)
					continue

				}
			}

		}
		if err := s.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "reading standard input:", err)
		}
		close(results)
	}()

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	if *unique {
		for res := range results {
			if isUnique(res) {
				fmt.Fprintln(w, res)
			}
		}
	}
	for res := range results {
		fmt.Fprintln(w, res)
	}

}

// parseHeaders does validation of headers input and saves it to a formatted map.
func parseHeaders(rawHeaders string) error {
	if rawHeaders != "" {
		if !strings.Contains(rawHeaders, ":") {
			return errors.New("headers flag not formatted properly (no colon to separate header and value)")
		}

		headers = make(map[string]string)
		rawHeaders := strings.Split(rawHeaders, ";;")
		for _, header := range rawHeaders {
			var parts []string
			if strings.Contains(header, ": ") {
				parts = strings.SplitN(header, ": ", 2)
			} else if strings.Contains(header, ":") {
				parts = strings.SplitN(header, ":", 2)
			} else {
				continue
			}
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return nil
}

// extractHostname() extracts the hostname from a URL and returns it
func extractHostname(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil || !u.IsAbs() {
		return "", errors.New("Input must be a valid absolute URL")
	}

	return u.Hostname(), nil
}

// print result constructs output lines and sends them to the results chan
func printResult(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan string, e *colly.HTMLElement) {
	result := e.Request.AbsoluteURL(link)
	whereURL := e.Request.URL.String()
	if result != "" {
		if showJson {
			where := ""
			if showWhere {
				where = whereURL
			}
			bytes, _ := json.Marshal(Result{
				Source: sourceName,
				URL:    result,
				Where:  where,
			})
			result = string(bytes)
		} else if showSource {
			result = "[" + sourceName + "] " + result
		}

		if showWhere && !showJson {
			result = "[" + whereURL + "] " + result
		}

		// If timeout occurs before goroutines are finished, recover from panic that may occur when attempting writing to results to closed results channel
		defer func() {
			if err := recover(); err != nil {
				return
			}
		}()
		results <- result
	}
}







func writewordlist(paramname string ){
    


dirname, err := os.UserHomeDir()
wordlistpath := dirname + "/list/hakrawler_parameters.txt"
    
file, err := os.OpenFile(wordlistpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    } 

  
    defer file.Close() 
var i int
        
    // Append data to the file
    if _, err := file.WriteString(paramname + "\n"); err != nil {
i+=1    
        log.Fatal(err)
    }   

removedupes(wordlistpath)
        
}



func removedupes(filepath string){
    file, err := os.Open(filepath)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    // Read the contents of the file into a slice of strings
    scanner := bufio.NewScanner(file)
    var lines []string
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }

    // Create a map to store the unique strings
    unique := make(map[string]bool)

    // Iterate over the slice of strings and add each string to the map as a key with a value of true
    for _, line := range lines {
        unique[line] = true
    }

    // Create a new slice of strings and append the keys of the map to it
    var uniqueLines []string
    for line := range unique {
        uniqueLines = append(uniqueLines, line)
    }

    // Write the contents of the new slice to the file
    output, err := os.Create(filepath)
    if err != nil {
        panic(err)
    }
    defer output.Close()

    for _, line := range uniqueLines {
        fmt.Fprintln(output, line)
    }

}



// returns whether the supplied url is unique or not
func isUnique(url string) bool {
	_, present := sm.Load(url)
	if present {
		return false
	}
	sm.Store(url, true)
	return true
}
