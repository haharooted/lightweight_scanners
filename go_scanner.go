package main

import (
	"net"
	"net/http"
	"sync"
	"net/url"
	"bufio"
	"flag"
	"fmt"
	"crypto/tls"
	"os"
	"time"
)

func main() {

	var session string
	flag.StringVar(&session, "s", "session=nulll", "(Default=Null) Set Cookie")

	var origin string
	flag.StringVar(&origin, "o", "bad.guy.com", "(Default=bag.guy.com) Set Origin Header")

	flag.Parse()

	origincheck(origin, session)

}

func IsURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func newClient() *http.Client {

	tr := &http.Transport{
		MaxIdleConns:    30,
		IdleConnTimeout: time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       time.Second * 10,
	}

}

func origincheck(origin string, session string) bool {
	client := newClient()
	var wg sync.WaitGroup
	sc := bufio.NewScanner(os.Stdin)
	status := false

	for sc.Scan() {
		rawURL := sc.Text()
		wg.Add(1)

		if IsURL(rawURL) == false {
			rawURL = "https://" + rawURL
		}

		go func() {
			defer wg.Done()

			req, err := http.NewRequest("GET", rawURL, nil)
			req.Header.Add("Origin", origin)
			req.Header.Add("Cookie", session)
			req.Header.Add("Host", rawURL)
			req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101")
			req.Header.Add("Accept-Language", "en-US,en;q=0.5")

			if err != nil {
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("Connection to server not available %s", err.Error())
				return
			}
			defer resp.Body.Close()
			header := resp.Header.Get("Access-Control-Allow-Origin")
			if header == origin {

				if header == "null" && resp.Header.Get("Access-Control-Allow-Credentials") == "true" {

					fmt.Printf("[%s] Reflected Origin: %s, credentials: %s, - URL: %s\n", aurora.BgBrightRed("VULN - Found Misconfigured! Null Origin Value and Credentials true").String(), origin, "true", rawURL)

				} else if header == "null" {

					fmt.Printf("[%s] Origin: %s - URL: %s\n", aurora.Red("VULN - Found Misconfigured! with Null Origin Value (NULL)").String(), origin, rawURL)

				} else if header == origin && resp.Header.Get("Access-Control-Allow-Credentials") == "true" {

					fmt.Printf("[%s] Reflected Origin: %s, credentials: %s, - URL: %s\n", aurora.BrightMagenta("VULN - Found Misconfigured! Relefected Origin With Credentials True").String(), origin, "true", rawURL)

				} else {

					fmt.Printf("[%s] Origin: %s - URL: %s\n", aurora.BrightMagenta("VULN - Found Misconfigured! with Refelected Origin").String(), origin, rawURL)

				}
				status = true

			} else if header == "*" && resp.Header.Get("Access-Control-Allow-Credentials") == "true" {
				fmt.Printf("[%s] %s\n", aurora.BrightYellow("VULN - Found! configured with Wildcard (*) and Credentials Value").String(), rawURL)
				status = true
			} else if header == "*" {
				fmt.Printf("[%s] %s\n", aurora.BrightYellow("VULN - Found! configured with Wildcard (*)").String(), rawURL)
			}
		}()

	}
	wg.Wait()
	return status
}