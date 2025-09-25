package crlf

import (
    "bufio"
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "math/rand"
    "net/url"
    "os"
    "strings"
    "time"

    "pohek/internal/engine"
)

// RunPrecheck filters CRLF payload types that consistently trigger 403 on the target.
// Strategy mirrors scpt's precheck but only considers 403:
// 1) Host baseline (/rand/ + payload) — mark payloads that return 403 for confirmation.
// 2) Confirm on up to 3 URLs from input file — drop payloads that return 403 across all samples.
// Returns payload names to KEEP. If an error occurs, returns original names (no filtering).
func RunPrecheck(ctx context.Context, deps engine.Deps) []string {
    names := []string{"x-header", "set-cookie", "http-x.x", "http-1.1-host"}
    base, err := deps.Opts.BuildBaseURL()
    if err != nil || base == "" { return names }

    fmt.Printf("[crlf-precheck] Running precheck for %s with %d payloads\n", base, len(names))

    marker := "precheck"
    enc := encodedByName(marker)

    // Phase 1: host baseline on /<rand>/
    rnd := randPath()
    var flagged403, nonflag []string
    for _, n := range names {
        select { case <-ctx.Done(): return names; default: }
        rawPath := "/" + rnd + "/" + enc[n]
        resp, err := deps.Client.Do(base, rawPath)
        if err != nil {
            nonflag = append(nonflag, n)
            continue
        }
        if resp.StatusCode == 403 {
            fmt.Printf("[crlf-precheck] %q returns 403 on host baseline; will confirm on sample URLs\n", n)
            flagged403 = append(flagged403, n)
        } else {
            nonflag = append(nonflag, n)
        }
    }

    samples := sampleURLs(deps.Opts.Wordlist, 3)
    if len(samples) == 0 {
        if len(flagged403) > 0 {
            fmt.Printf("[crlf-precheck] No sample URLs; conservatively filtering %d flagged payload(s)\n", len(flagged403))
        }
        return nonflag
    }

    // Confirm flagged403 across samples
    var confirmedDrop, recovered []string
    for _, n := range flagged403 {
        select { case <-ctx.Done(): return append([]string{}, nonflag...) ; default: }
        all403 := true
        var confirmedURL string
        for _, raw := range samples {
            u, perr := url.Parse(raw)
            if perr != nil || u.Scheme == "" || u.Host == "" { continue }
            baseURL := u.Scheme + "://" + u.Host
            pth := u.EscapedPath()
            if pth == "" { pth = "/" }
            if !strings.HasSuffix(pth, "/") { pth = pth + "/" }
            rp := pth + enc[n]
            if u.RawQuery != "" { rp += "?" + u.RawQuery }
            resp, err := deps.Client.Do(baseURL, rp)
            if err != nil { all403 = false; break }
            if resp.StatusCode != 403 { all403 = false; break }
            if confirmedURL == "" { confirmedURL = baseURL + rp }
        }
        if all403 {
            confirmedDrop = append(confirmedDrop, n)
            if confirmedURL != "" {
                fmt.Printf("[crlf-precheck] Rechecking %q with %s. 403 confirmed; filtered out\n", n, confirmedURL)
            } else {
                fmt.Printf("[crlf-precheck] Rechecking %q. 403 confirmed across samples; filtered out\n", n)
            }
        } else {
            recovered = append(recovered, n)
        }
    }

    // Verify non-flagged: drop if 403 across all samples
    final := make([]string, 0, len(nonflag)+len(recovered))
    var extraDrop []string
    for _, n := range nonflag {
        select { case <-ctx.Done(): return append(final, recovered...) ; default: }
        all403 := true
        for _, raw := range samples {
            u, perr := url.Parse(raw)
            if perr != nil || u.Scheme == "" || u.Host == "" { continue }
            baseURL := u.Scheme + "://" + u.Host
            pth := u.EscapedPath()
            if pth == "" { pth = "/" }
            if !strings.HasSuffix(pth, "/") { pth = pth + "/" }
            rp := pth + enc[n]
            if u.RawQuery != "" { rp += "?" + u.RawQuery }
            resp, err := deps.Client.Do(baseURL, rp)
            if err != nil { all403 = false; break }
            if resp.StatusCode != 403 { all403 = false }
            if !all403 { break }
        }
        if all403 {
            extraDrop = append(extraDrop, n)
        } else {
            final = append(final, n)
        }
    }

    // Merge recovered
    final = append(final, recovered...)
    if len(confirmedDrop)+len(extraDrop) > 0 {
        fmt.Printf("[crlf-precheck] Filtered payloads: %s\n", strings.Join(append(confirmedDrop, extraDrop...), ", "))
    } else {
        fmt.Printf("[crlf-precheck] No payloads filtered\n")
    }
    return final
}

func encodedByName(marker string) map[string]string {
    return map[string]string{
        "x-header":       "%0d%0aX-Header-" + marker + ": 1",
        "set-cookie":     "%0d%0aSet-Cookie: test_cookie_" + marker + "=1",
        "http-x.x":       "%20HTTP/X.X%20",
        "http-1.1-host":  "%20HTTP/1.1%0d%0aHost:",
    }
}

func randPath() string {
    var b [8]byte
    _, _ = rand.Read(b[:])
    return hex.EncodeToString(b[:])
}

// sampleURLs performs a reservoir sampling (Algorithm R) of up to k URLs from file.
// It only considers absolute URLs with a non-empty path different from "/".
func sampleURLs(filepath string, k int) []string {
    f, err := os.Open(filepath)
    if err != nil { return nil }
    defer f.Close()
    sc := bufio.NewScanner(f)
    out := make([]string, 0, k)
    count := 0
    rand.Seed(time.Now().UnixNano())
    for sc.Scan() {
        raw := strings.TrimSpace(sc.Text())
        if raw == "" { continue }
        u, perr := url.Parse(raw)
        if perr != nil || u.Scheme == "" || u.Host == "" { continue }
        p := u.Path
        if p == "" || p == "/" { continue }
        count++
        if len(out) < k { out = append(out, raw); continue }
        j := rand.Intn(count)
        if j < k { out[j] = raw }
    }
    return out
}

