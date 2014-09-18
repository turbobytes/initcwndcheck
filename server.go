package main

//Originally stollen from https://github.com/kdar/gorawtcpsyn/blob/master/main.go

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/turbobytes/initcwndcheck/checker"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type Result struct {
	PktCount, PayloadSize, TotalPayloadSize int
	PayloadHexDump                          string
	Err                                     string
	Ip                                      string
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "homepage.html")
}

func serve(w http.ResponseWriter, r *http.Request, res *Result) {
	b, _ := json.Marshal(res)
	cb := r.FormValue("callback")
	if cb == "" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%s", b)
	} else {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "%s && %s (%s)", cb, cb, b)
	}
}

func getfullbodysize(c chan int, req *http.Request) {
	tr := &http.Transport{}
	res, _ := tr.RoundTrip(req)
	b, _ := httputil.DumpResponse(res, true)
	c <- len(b)
}

func handler(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.FormValue("url"))
	if err != nil {
		serve(w, r, &Result{Err: err.Error()})
		return
	}
	hostname := u.Host
	if hostname == "" {
		serve(w, r, &Result{Err: "Can't get Hostname"})
		return
	}

	path := u.Path
	if u.RawQuery != "" {
		path = fmt.Sprintf("%s?%s", u.Path, u.RawQuery)
	}
	fmt.Println(hostname)
	fmt.Println(path)
	endpoint := r.FormValue("endpoint")

	var dstip net.IP
	if endpoint == "" {
		endpoint = hostname
	}
	ipstr := r.FormValue("ip")
	if ipstr == "" {
		dstaddrs, err := net.LookupIP(endpoint)
		if err != nil {
			serve(w, r, &Result{Err: err.Error()})
			return
		}
		dstip = dstaddrs[0].To4()
	} else {
		dstip = net.ParseIP(ipstr)
	}
	fmt.Println(dstip)
	if dstip == nil {
		serve(w, r, &Result{Err: "ip error"})
		return
	}
	c_fullpayload := make(chan int)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s%s", dstip.String(), path), nil)
	req.Host = hostname
	go getfullbodysize(c_fullpayload, req)
	pkt_count, payload_size, fullpayload, err := initcwndcheck.Detectinitcwnd(hostname, path, dstip)
	fullpayloadsize := <-c_fullpayload
	if err != nil {
		serve(w, r, &Result{pkt_count, payload_size, fullpayloadsize, hex.Dump(fullpayload), err.Error(), dstip.String()})
	} else {
		serve(w, r, &Result{pkt_count, payload_size, fullpayloadsize, hex.Dump(fullpayload), "", dstip.String()})
	}

}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/runtest", handler)
	s := &http.Server{
		Addr: ":8565",
	}
	log.Fatal(s.ListenAndServe())
	/*
		if len(os.Args) != 3 {
			log.Printf("Usage: %s <host/ip> <path>\n", os.Args[0])
			os.Exit(-1)
		}

		log.Println("starting")
		//Prepare http payload
		//Resolve destination
		dstaddrs, err := net.LookupIP(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		// parse the destination host and port from the command line os.Args
		dstip := dstaddrs[0].To4()
		pkt_count, payload_size, fullpayload, err := detectinitcwnd(os.Args[1], os.Args[2], dstip)
		fmt.Println(hex.Dump(fullpayload))
		fmt.Printf("Packet Count: %d\nData downloaded: %d\nErr: %v\n", pkt_count, payload_size, err)
	*/
}
