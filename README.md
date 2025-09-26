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
  - `--crlf`: enable CRLF injection module (default false)
  

Behavior changes
- Removed path-list mode (hostname + directory wordlist). Only URL-file input is supported now.
- The `--urlfile` flag was removed; the tool always expects absolute URLs in the input file.

SCPT payload precheck (runs by default)
1) Host baseline: requests `/<random>/ + payload` on the base host. Payloads that return 302 or 403 are flagged.
2) Sample verify: samples up to 3 URLs from the input file. If a payload returns 302 or 403 on all samples, it’s dropped.
3) Scanning proceeds with the filtered payloads only for SCPT.

Note
- If all payloads are filtered by precheck (302/403), the scan stops early with a message instead of proceeding with an empty set.

Output
- Stdout: one line per finding, prints full URL once, payload, status, and signals.
- JSONL: per-host file in the chosen output directory, one JSON object per line.

CRLF module (`--crlf`)
- Purpose: probe for CRLF injection and related parser confusions via path/query mutations.
- Payloads used:
  - `%0d%0aX-Header-<rand>: 1`
  - `%0d%0aSet-Cookie: test_cookie_<rand>=1`
  - `%20HTTP/X.X%20`
  - `%20HTTP/1.1%0d%0aHost:`
- Injection points per URL:
  - Path: after each segment, at end, and with an extra trailing segment.
  - Query: appended to each parameter value; seeded as `q=1<payload>` if no query present.
- Redirects: leave `--followredirects=false` (default) to inspect intermediate 30x responses.
- Detection evidence (per single probe; no baseline, no repetition):
  - HTTP status `400`.
  - Response header named `X-Header-<rand>` present (case-insensitive; value ignored).
  - `Set-Cookie` exactly `test_cookie_<rand>=1` (attributes ignored).
  - Body contains any: `Invalid`, `HTTP version`, `HTTP header`, `Host header` (case-insensitive).
- Retries/429: reuses the same timeout/retry/backoff behavior as SCPT via the shared HTTP client.
- Precheck (runs by default for CRLF):
  - Phase 1: host baseline `/rand/ + payload` and flag payloads that return 403.
  - Phase 2: confirm on up to 3 random URLs; drop payloads that return 403 across all samples.

Examples
- Run only CRLF module:
  - `./scscanner --crlf --scpt=false example.com urls.txt`
- Run both SCPT and CRLF:
  - `./scscanner --scpt --crlf example.com urls.txt`
