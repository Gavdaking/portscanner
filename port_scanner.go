package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// holds info about a scanned port
type ScanResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

// checks if a port is open and grabs banner if needed
func worker(wg *sync.WaitGroup, jobs chan string, results chan ScanResult, d net.Dialer, grab bool) {
	defer wg.Done()

	for address := range jobs {
		host, portStr, _ := net.SplitHostPort(address)
		portNum, _ := strconv.Atoi(portStr)

		conn, err := d.Dial("tcp", address)
		if err == nil {
			var banner string
			if grab {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				banner = string(buf[:n])
			}
			conn.Close()
			results <- ScanResult{Target: host, Port: portNum, Open: true, Banner: banner}
		} else {
			results <- ScanResult{Target: host, Port: portNum, Open: false}
		}
	}
}

func main() {
	var targetList string
	var startPort, endPort int
	var numWorkers int
	var timeoutSec int
	var jsonOut bool
	var portInput string
	var grabBanner bool

	// set up flags
	flag.StringVar(&targetList, "targets", "scanme.nmap.org", "List of targets separated by commas")
	flag.IntVar(&startPort, "start-port", 1, "Start port number")
	flag.IntVar(&endPort, "end-port", 1024, "End port number")
	flag.IntVar(&numWorkers, "workers", 100, "How many goroutines to use")
	flag.IntVar(&timeoutSec, "timeout", 5, "Timeout per connection in seconds")
	flag.BoolVar(&jsonOut, "json", false, "Show results in JSON")
	flag.StringVar(&portInput, "ports", "", "Comma-separated list of ports (optional)")
	flag.BoolVar(&grabBanner, "banner", false, "Try to read banner from open port")
	flag.Parse()

	targets := strings.Split(targetList, ",")

	dialer := net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	jobs := make(chan string, 100)
	results := make(chan ScanResult, 100)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, dialer, grabBanner)
	}

	var ports []int
	if portInput != "" {
		portParts := strings.Split(portInput, ",")
		for _, p := range portParts {
			pInt, err := strconv.Atoi(p)
			if err == nil {
				ports = append(ports, pInt)
			} else {
				fmt.Println("Ignoring bad port:", p)
			}
		}
	} else {
		for p := startPort; p <= endPort; p++ {
			ports = append(ports, p)
		}
	}

	startTime := time.Now()

	// send scan jobs to workers
	go func() {
		for _, tgt := range targets {
			for _, prt := range ports {
				addr := net.JoinHostPort(tgt, strconv.Itoa(prt))
				jobs <- addr
				fmt.Println("Queued:", addr)
			}
		}
		close(jobs)
	}()

	// wait for everything to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []ScanResult
	for r := range results {
		if r.Open {
			openPorts = append(openPorts, r)
		}
	}

	duration := time.Since(startTime)

	// output results
	if jsonOut {
		jsonRes, _ := json.MarshalIndent(openPorts, "", "  ")
		fmt.Println(string(jsonRes))
	} else {
		fmt.Println("Scan done!")
		fmt.Println("Open Ports:", len(openPorts))
		fmt.Println("Scanned:", len(targets)*len(ports))
		fmt.Println("Took:", duration)

		if len(openPorts) > 0 {
			fmt.Println("Open Ports List:")
			for _, item := range openPorts {
				fmt.Printf(" - %s:%d", item.Target, item.Port)
				if grabBanner && item.Banner != "" {
					fmt.Printf(" | Banner: %s", item.Banner)
				}
				fmt.Println()
			}
		} else {
			fmt.Println("No open ports found.")
		}
	}
}
