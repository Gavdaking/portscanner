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

type ScanResult struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

// Worker function to scan ports concurrently
func worker(wg *sync.WaitGroup, tasks chan string, results chan ScanResult, dialer net.Dialer, grabBanner bool) {
	defer wg.Done()
	for addr := range tasks {
		target, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		conn, err := dialer.Dial("tcp", addr)
		if err == nil {
			var banner string
			if grabBanner {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				banner = string(buf[:n]) // Capture potential server response (if any)
			}
			conn.Close()
			results <- ScanResult{Target: target, Port: port, Open: true, Banner: banner}
		} else {
			results <- ScanResult{Target: target, Port: port, Open: false}
		}
	}
}

func main() {
	var targetsStr string
	var startPort, endPort, workers, timeout int
	var portsList string
	var jsonOutput, grabBanner bool

	// Command-line flags for user customization
	flag.StringVar(&targetsStr, "targets", "scanme.nmap.org", "Comma-separated list of targets")
	flag.IntVar(&startPort, "start-port", 1, "Start port")
	flag.IntVar(&endPort, "end-port", 1024, "End port")
	flag.IntVar(&workers, "workers", 100, "Number of concurrent workers")
	flag.IntVar(&timeout, "timeout", 5, "Timeout in seconds per connection")
	flag.BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	flag.StringVar(&portsList, "ports", "", "Comma-separated list of specific ports to scan")
	flag.BoolVar(&grabBanner, "banner", false, "Enable banner grabbing")
	flag.Parse()

	targets := strings.Split(targetsStr, ",")
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	tasks := make(chan string, 100)
	results := make(chan ScanResult, 100)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(&wg, tasks, results, dialer, grabBanner)
	}

	var ports []int
	if portsList != "" {
		for _, p := range strings.Split(portsList, ",") {
			port, err := strconv.Atoi(p)
			if err == nil {
				ports = append(ports, port)
			} else {
				fmt.Printf("Invalid port: %s\n", p) // Ignore invalid port input
			}
		}
	} else {
		for p := startPort; p <= endPort; p++ {
			ports = append(ports, p)
		}
	}

	startTime := time.Now()

	// Start feeding the worker tasks
	go func() {
		for _, target := range targets {
			for _, port := range ports {
				address := net.JoinHostPort(target, strconv.Itoa(port))
				tasks <- address
				fmt.Printf("Queueing scan for %s:%d\n", target, port) // Indicate scan progress
			}
		}
		close(tasks)
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []ScanResult
	for res := range results {
		if res.Open {
			openPorts = append(openPorts, res)
		}
	}
	duration := time.Since(startTime)

	// Print results in either JSON or readable format
	if jsonOutput {
		jsonData, _ := json.MarshalIndent(openPorts, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("\nScan complete. Results:\n")
		fmt.Printf("Open Ports: %d\n", len(openPorts))
		fmt.Printf("Total Ports Scanned: %d\n", len(targets)*len(ports))
		fmt.Printf("Time Taken: %s\n", duration)
		if len(openPorts) > 0 {
			fmt.Println("Open ports:")
			for _, res := range openPorts {
				fmt.Printf("- %s:%d (Banner: %s)\n", res.Target, res.Port, res.Banner)
			}
		} else {
			fmt.Println("No open ports detected.") // message if no results
		}
	}
}
