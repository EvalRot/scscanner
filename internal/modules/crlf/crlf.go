package crlf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"pohek/internal/engine"
	"pohek/internal/httpx"
	"pohek/internal/output"
)

// Module implements CRLF injection checks as a pluggable module.
// It mirrors scpt's retry/429 handling and output style per project conventions.
type Module struct{
    allowed map[string]bool // nil means all
}

func (Module) Name() string { return "crlf" }

// DedupKey implements engine.DedupKeyer. CRLF treats path+query distinctly,
// so use the raw target path (including query) as part of the key.
func (Module) DedupKey(t engine.Target) string {
    return t.BaseURL + " " + t.Path
}

// New creates a CRLF module with an optional allowed payload name list from precheck.
func New(allowed []string) Module {
    m := Module{}
    if len(allowed) > 0 {
        m.allowed = make(map[string]bool, len(allowed))
        for _, n := range allowed { m.allowed[n] = true }
    }
    return m
}

// Process runs CRLF probes against the provided target.
// No baseline or verification is performed per requirements.
func (m Module) Process(ctx context.Context, deps engine.Deps, t engine.Target, base *httpx.Response) error {
    // Build a per-run marker
    marker := randHex(6)
    // Build payloads and apply precheck allow-list if present
    payloads := buildPayloads(marker)
    if m.allowed != nil {
        filtered := make([]payload, 0, len(payloads))
        for _, p := range payloads { if m.allowed[p.name] { filtered = append(filtered, p) } }
        payloads = filtered
        if len(payloads) == 0 { return nil }
    }

    // Split original path into path + raw query (do not decode)
    path, rawQuery := splitPathQuery(t.Path)

    // Generate candidates: path and query variants
    candidates := make([]candidate, 0, 64)
    for _, p := range payloads {
        // Path: insert after each segment delimiter '/'
        for _, i := range segmentBoundaries(path) {
            mutated := path[:i] + p.encoded + path[i:]
            final := mutated
            if rawQuery != "" { final += "?" + rawQuery }
            candidates = append(candidates, candidate{raw: final, p: p, point: "path@seg"})
        }
        // Path: end of path
        end := path + p.encoded
        if rawQuery != "" { end += "?" + rawQuery }
        candidates = append(candidates, candidate{raw: end, p: p, point: "path@end"})
        // Path: extra trailing segment
        extra := path + p.encoded + "/x"
        if rawQuery != "" { extra += "?" + rawQuery }
        candidates = append(candidates, candidate{raw: extra, p: p, point: "path@extra"})

        // Query: append to each value or seed if none
        if rawQuery == "" {
            q := "q=1" + p.encoded
            candidates = append(candidates, candidate{raw: path+"?"+q, p: p, point: "query@seed"})
        } else {
            parts := strings.Split(rawQuery, "&")
            for idx := range parts {
                cp := make([]string, len(parts))
                copy(cp, parts)
                kv := cp[idx]
                if eq := strings.IndexByte(kv, '='); eq >= 0 {
                    cp[idx] = kv[:eq+1] + kv[eq+1:] + p.encoded
                } else {
                    cp[idx] = kv + "=" + p.encoded
                }
                q := strings.Join(cp, "&")
                candidates = append(candidates, candidate{raw: path+"?"+q, p: p, point: "query@value"})
            }
        }
    }

    // For each candidate, perform request with scpt-like retry/429 handling
    for _, c := range candidates {
        select { case <-ctx.Done(): return ctx.Err(); default: }
        retries := deps.Opts.Retry
        for attempt := 0; attempt <= retries; attempt++ {
            resp, err := deps.Client.Do(t.BaseURL, c.raw)
            if err != nil {
                if attempt < retries { continue }
                // backoff jitter similar to scpt on final failure
                time.Sleep(time.Duration(2+attempt) * time.Second)
                break
            }

            if resp.StatusCode == 429 {
                if attempt < retries {
                    if resp.RetryAfter > 0 {
                        time.Sleep(resp.RetryAfter)
                    } else {
                        base := 1 << attempt
                        if base > 8 { base = 8 }
                        d := time.Duration(base) * time.Second
                        d += time.Duration((attempt*97)%300) * time.Millisecond
                        time.Sleep(d)
                    }
                    continue
                }
                break
            }

            // Evaluate evidence (each condition produces a finding; no dedup/short-circuit)
            notes := []string{}
            signals := map[string]bool{"status400": false, "xheader": false, "setcookie": false, "keyword": false}

            if resp.StatusCode == 400 {
                signals["status400"] = true
                notes = append(notes, "HTTP 400 status")
                emitFinding(deps, t.BaseURL, t.Path, t.BaseURL+c.raw, c.p.encoded, resp, signals, notes)
            }

            // Header: X-Header-<marker> present (value ignored)
            if hasHeaderCI(resp, "X-Header-"+marker) {
                signals = map[string]bool{"status400": resp.StatusCode == 400, "xheader": true, "setcookie": false, "keyword": false}
                notes = []string{"X-Header-" + marker + " present"}
                emitFinding(deps, t.BaseURL, t.Path, t.BaseURL+c.raw, c.p.encoded, resp, signals, notes)
            }

            // Set-Cookie exact match of injected cookie
            if c.p.cookieName != "" && hasInjectedCookie(resp, c.p.cookieName, c.p.cookieVal) {
                signals = map[string]bool{"status400": resp.StatusCode == 400, "xheader": false, "setcookie": true, "keyword": false}
                notes = []string{fmt.Sprintf("Set-Cookie %s=%s present", c.p.cookieName, c.p.cookieVal)}
                emitFinding(deps, t.BaseURL, t.Path, t.BaseURL+c.raw, c.p.encoded, resp, signals, notes)
            }

            if kw, ok := bodyHasKeyword(resp.Body); ok {
                signals = map[string]bool{"status400": resp.StatusCode == 400, "xheader": false, "setcookie": false, "keyword": true}
                notes = []string{"body contains: " + kw}
                emitFinding(deps, t.BaseURL, t.Path, t.BaseURL+c.raw, c.p.encoded, resp, signals, notes)
            }
            break
        }
    }
    return nil
}

// Types and helpers
type payload struct {
    name       string
    encoded    string
    cookieName string
    cookieVal  string
}

type candidate struct {
    raw   string
    p     payload
    point string
}

func buildPayloads(marker string) []payload {
    return []payload{
        {name: "x-header", encoded: "%0d%0aX-Header-" + marker + ":%201"},
        {name: "set-cookie", encoded: "%0d%0aSet-Cookie:%20test_cookie_" + marker + "=1", cookieName: "test_cookie_" + marker, cookieVal: "1"},
        {name: "http-x.x", encoded: "%20HTTP/X.X%20"},
        {name: "http-1.1-host", encoded: "%20HTTP/1.1%0d%0aHost:"},
    }
}

func randHex(n int) string {
    if n <= 0 { n = 6 }
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil { return "deadbeef" }
    return hex.EncodeToString(b)
}

func splitPathQuery(raw string) (string, string) {
    if raw == "" { return "/", "" }
    if i := strings.IndexByte(raw, '?'); i >= 0 {
        return raw[:i], raw[i+1:]
    }
    return raw, ""
}

// segmentBoundaries returns indexes of '/' in path (excluding the leading one at index 0),
// to insert payload after each segment.
func segmentBoundaries(path string) []int {
    var idx []int
    for i := 1; i < len(path); i++ {
        if path[i] == '/' { idx = append(idx, i) }
    }
    return idx
}

func hasHeaderCI(resp *httpx.Response, name string) bool {
    for k := range resp.Headers {
        if strings.EqualFold(k, name) { return true }
    }
    return false
}

func hasInjectedCookie(resp *httpx.Response, cname, cval string) bool {
    vals := resp.Headers.Values("Set-Cookie")
    if len(vals) == 0 { return false }
    target := cname + "=" + cval
    for _, v := range vals {
        semi := strings.IndexByte(v, ';')
        pair := v
        if semi >= 0 { pair = v[:semi] }
        pair = strings.TrimSpace(pair)
        if strings.EqualFold(pair, target) { return true }
    }
    return false
}

func bodyHasKeyword(body []byte) (string, bool) {
    if len(body) == 0 { return "", false }
    s := strings.ToLower(string(body))
    keys := []string{"invalid", "http version", "http header", "host header"}
    for _, k := range keys {
        if strings.Contains(s, k) { return k, true }
    }
    return "", false
}

func emitFinding(deps engine.Deps, baseURL, path, urlSent, payload string, resp *httpx.Response, signals map[string]bool, notes []string) {
    f := &output.Finding{
        Module:    "crlf",
        Timestamp: time.Now(),
        Host:      baseURL,
        Path:      path,
        Payload:   payload,
        URL:       urlSent,
        Signals:   signals,
        Notes:     notes,
        Status:    resp.StatusCode,
        Server:    resp.Headers.Get("Server"),
        ContentType: resp.Headers.Get("Content-Type"),
    }
    _ = deps.Sink.Write(f)
}

// Optional sanity helper for manual testing; not used by engine.
func buildURL(base, raw string) string {
    u, _ := url.Parse(base)
    u2 := *u
    u2.Opaque = raw
    return u2.String()
}
