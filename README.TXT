# Go Port Scanner

A fast and concurrent port scanning tool written in **Go**. It scans specified ports on target hosts and optionally performs **banner grabbing** 
to identify running services.

## Features
- Scans a range of ports or specific ports on given targets
- Supports **concurrent scanning** for faster results
- Customizable **timeout** settings
- **Banner grabbing** to identify running services (optional)
- Output results in **JSON** format (optional)

## How to Build and Run

### Prerequisites
- Install **Go**: [Download & Install Go](https://go.dev/dl/)

### Clone the Repository
```sh
git clone https://github.com/your-repo/port-scanner.git
cd port-scanner
```

### Build the Project
```sh
go build -o port_scanner port_scanner.go
```

### Run the Scanner
```sh
go run port_scanner.go -targets=scanme.nmap.org -start-port=20 -end-port=100 -workers=50 -timeout=3 -json
```

## Sample Output

### Default Output (Readable Format)
```
Queueing scan for scanme.nmap.org:22
Queueing scan for scanme.nmap.org:80
Queueing scan for scanme.nmap.org:443
...

Scan complete. Results:
Open Ports: 2
Total Ports Scanned: 100
Time Taken: 3.2s

Open ports:
- scanme.nmap.org:22 (Banner: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2)
- scanme.nmap.org:80 (Banner: Apache HTTP Server)
```

### JSON Output (`-json` flag)
```json
[
  {
    "target": "scanme.nmap.org",
    "port": 22,
    "open": true,
    "banner": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
  },
  {
    "target": "scanme.nmap.org",
    "port": 80,
    "open": true,
    "banner": "Apache HTTP Server"
  }
]
```
Youtude link: https://youtu.be/x9LXJ3wuEd8
