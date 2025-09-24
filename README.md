SCScanner — Secondary Context Path Traversal Scanner

Usage
- Build: `go build -o scscanner .`
- Run: `./scscanner <hostname> <url_file> [flags]`

Positional args
- `hostname`: the primary host to scan (used for precheck base URL and validation).
- `url_file`: a file with absolute URLs (all URLs should belong to the same host).

Key flags
- `--threads, -t`: number of concurrent targets (default 15)
- `--timeout`: request timeout seconds (default 5)
- `--followredirects`: follow HTTP redirects (default false)
- `--insecure`: ignore TLS validation (default true)
- `--output`: output directory for JSONL per host (use `no.no` for stdout)
 - `--proxy`, `--proxy-url`: proxy configuration
 - `--scpt`: enable SCPT module (default true)
 - `--scpt-precheck`: enable payload precheck to filter normalization redirects (302) and consistent WAF blocks (403)

Behavior changes
- Removed path-list mode (hostname + directory wordlist). Only URL-file input is supported now.
- The `--urlfile` flag was removed; the tool always expects absolute URLs in the input file.

SCPT payload precheck (`--scpt-precheck`)
1) Host baseline: requests `/<random>/ + payload` on the base host. Payloads that return 302 are dropped.
2) Sample verify: samples up to 3 URLs from the input file. If a payload returns 302 on all samples, it’s dropped.
3) Scanning proceeds with the filtered payloads only.

Note
- If all payloads are filtered by precheck (302/403), the scan stops early with a message instead of proceeding with an empty set.

Output
- Stdout: one line per finding, prints full URL once, payload, status, and signals.
- JSONL: per-host file in the chosen output directory, one JSON object per line.
