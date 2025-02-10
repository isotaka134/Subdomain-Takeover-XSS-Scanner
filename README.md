# Subdomain Takeover & XSS Scanner

## Description
This Metasploit auxiliary module scans a list of subdomains to check for active hosts, takeover vulnerabilities, and potential XSS flaws. 

## Features
- Scans subdomains from a file
- Detects potential subdomain takeovers
- Checks for XSS vulnerabilities using a set of payloads
- Saves results to an output file

## Installation
Ensure you have Metasploit Framework installed on your system.

## Usage
### 1. Load the module in Metasploit:
```bash
msfconsole
```

### 2. Load the module:
```bash
use auxiliary/scanner/subdomain_xss
```

### 3. Set required options:
```bash
set FILE subdomains.txt
set OUTPUT results.txt
```

### 4. Run the scanner:
```bash
run
```

## Options
| Option  | Description |
|---------|-------------|
| `FILE`  | Path to the subdomain list file (required) |
| `OUTPUT`| Path to save results (default: `results.txt`) |

## Example Output
```bash
[*] Checking example.com
[+] Active: example.com (200)
[!] Potential Takeover: takeover.example.com
[!] XSS Vulnerable: vulnerable.example.com with payload: <script>alert('XSS')</script>
[+] Scan completed! Results saved in results.txt
```

## Notes
- Ensure your subdomain list file contains one subdomain per line.
- The module checks for takeover by detecting unconfigured domains.
- XSS detection is based on reflected payloads in HTTP responses.

## License
This project is licensed under the MIT License.

## Author
- HAMZA EL-HAMDAOUI
