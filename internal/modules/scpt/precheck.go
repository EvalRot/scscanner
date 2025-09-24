package scpt

import (
    "bufio"
    "context"
    crand "crypto/rand"
    "encoding/hex"
    "fmt"
    mrand "math/rand"
    "net/url"
    "os"
    "strings"
    "time"

    "pohek/internal/engine"
)

// RunPrecheck filters out traversal payloads that consistently trigger 302
// normalization redirects or 403 WAF blocks on the target host. It performs two phases:
// 1) Host baseline: request /<random>/ + payload; drop payloads returning 302 or 403.
// 2) Sample verify: on up to 5 random URLs from the input file, if a payload
//    returns 302 (redirect) or 403 (forbidden) for all samples, drop it.
// Returns the filtered payload list (may be empty). Any errors are treated as
// no-filter (return original list).
func RunPrecheck(ctx context.Context, deps engine.Deps) []string {
    orig := deps.Payloads.Items()
    if len(orig) == 0 {
        return nil
    }
    base, err := deps.Opts.BuildBaseURL()
    if err != nil || base == "" {
        return orig
    }

    fmt.Printf("[scpt-precheck] Running precheck module for %s with %d payloads\n", base, len(orig))

    // Phase 1: random non-existent baseline
    rnd := randPath()
    fmt.Printf("[scpt-precheck] Checking %s/%s/ with traversal payloads\n", base, rnd)

    // Separate payloads by behavior on the random non-existent path
    var (
        flagged302 []string // 302 on /<rand>/ – need confirmation on real URLs
        flagged403 []string // 403 on /<rand>/ – need confirmation on real URLs
        nonflag    []string // not 302/403 – still verify on samples to be safe
    )
    for _, p := range orig {
        select { case <-ctx.Done(): return orig; default: }
        path := "/" + rnd + "/" + p
        resp, err := deps.Client.Do(base, path)
        if err != nil {
            // Keep conservative: treat as non-flagged so it stays for scanning
            nonflag = append(nonflag, p)
            continue
        }
        switch resp.StatusCode {
        case 302:
            fmt.Printf("[scpt-precheck] The payload %q returns 302, will check again with a URL from the file\n", p)
            flagged302 = append(flagged302, p)
        case 403:
            fmt.Printf("[scpt-precheck] The payload %q returns 403, will check again with a URL from the file\n", p)
            flagged403 = append(flagged403, p)
        default:
            nonflag = append(nonflag, p)
        }
    }

    // Phase 2: sample verification on up to 3 URLs from input file
    samples := sampleURLs(deps.Opts.Wordlist, 3)
    if len(samples) == 0 {
        // No samples; keep non-flagged, drop flagged (conservative filtering)
        dropped := len(flagged302) + len(flagged403)
        if dropped > 0 {
            fmt.Printf("[scpt-precheck] No sample URLs available; conservatively filtering %d flagged payload(s)\n", dropped)
        }
        return nonflag
    }

    // Confirm flagged ones across samples; keep only those not 302/403 everywhere
    var (
        confirmedDrop []string
        recovered     []string
    )
    // Confirm 302-flagged
    for _, p := range flagged302 {
        select { case <-ctx.Done(): return append([]string{}, nonflag...) ; default: }
        all302 := true
        var confirmedURL string
        for _, raw := range samples {
            u, err := url.Parse(raw)
            if err != nil || u.Scheme == "" || u.Host == "" { continue }
            baseURL := u.Scheme + "://" + u.Host
            // Preserve original escaping; append payload before query string.
            pth := u.EscapedPath()
            if pth == "" { pth = "/" }
            if !strings.HasSuffix(pth, "/") { pth = pth + "/" }
            rawPath := pth + p
            if u.RawQuery != "" { rawPath = rawPath + "?" + u.RawQuery }
            resp, err := deps.Client.Do(baseURL, rawPath)
            if err != nil { all302 = false; break }
            if resp.StatusCode != 302 { all302 = false; break }
            if confirmedURL == "" { confirmedURL = baseURL + rawPath }
        }
        if all302 {
            confirmedDrop = append(confirmedDrop, p)
            if confirmedURL != "" {
                fmt.Printf("[scpt-precheck] Rechecking payload %q with the URL %s. 302 Confirmed. The payload %q was filtered out\n", p, confirmedURL, p)
            } else {
                fmt.Printf("[scpt-precheck] Rechecking payload %q. 302 Confirmed across samples. The payload was filtered out\n", p)
            }
        } else {
            recovered = append(recovered, p)
        }
    }

    // Confirm 403-flagged
    for _, p := range flagged403 {
        select { case <-ctx.Done(): return append([]string{}, nonflag...) ; default: }
        all403 := true
        var confirmedURL string
        for _, raw := range samples {
            u, err := url.Parse(raw)
            if err != nil || u.Scheme == "" || u.Host == "" { continue }
            baseURL := u.Scheme + "://" + u.Host
            // Preserve original escaping; append payload before query string.
            pth := u.EscapedPath()
            if pth == "" { pth = "/" }
            if !strings.HasSuffix(pth, "/") { pth = pth + "/" }
            rawPath := pth + p
            if u.RawQuery != "" { rawPath = rawPath + "?" + u.RawQuery }
            resp, err := deps.Client.Do(baseURL, rawPath)
            if err != nil { all403 = false; break }
            if resp.StatusCode != 403 { all403 = false; break }
            if confirmedURL == "" { confirmedURL = baseURL + rawPath }
        }
        if all403 {
            confirmedDrop = append(confirmedDrop, p)
            if confirmedURL != "" {
                fmt.Printf("[scpt-precheck] Rechecking payload %q with the URL %s. 403 Confirmed. The payload %q was filtered out\n", p, confirmedURL, p)
            } else {
                fmt.Printf("[scpt-precheck] Rechecking payload %q. 403 Confirmed across samples. The payload was filtered out\n", p)
            }
        } else {
            recovered = append(recovered, p)
        }
    }

    // Also verify non-flagged payloads; drop if they show 302 or 403 across all samples
    final := make([]string, 0, len(nonflag)+len(recovered))
    var extraDrop []string
    for _, p := range nonflag {
        select { case <-ctx.Done(): return append(final, recovered...) ; default: }
        all302 := true
        all403 := true
        for _, raw := range samples {
            u, err := url.Parse(raw)
            if err != nil || u.Scheme == "" || u.Host == "" { continue }
            baseURL := u.Scheme + "://" + u.Host
            path := u.Path
            if u.RawQuery != "" { path = path + "?" + u.RawQuery }
            if path != "" && !strings.HasSuffix(path, "/") { path = path + "/" }
            resp, err := deps.Client.Do(baseURL, path+p)
            if err != nil { all302 = false; all403 = false; break }
            if resp.StatusCode != 302 { all302 = false }
            if resp.StatusCode != 403 { all403 = false }
            if !all302 && !all403 { break }
        }
        if all302 || all403 {
            extraDrop = append(extraDrop, p)
        } else {
            final = append(final, p)
        }
    }

    // Merge recovered flagged ones back
    final = append(final, recovered...)

    // Final summary
    var summary []string
    if len(confirmedDrop) > 0 { summary = append(summary, confirmedDrop...) }
    if len(extraDrop) > 0 { summary = append(summary, extraDrop...) }
    if len(summary) > 0 {
        fmt.Printf("[scpt-precheck] Payloads filtered after confirmation: %s\n", strings.Join(summary, ", "))
    } else {
        fmt.Printf("[scpt-precheck] No payloads were filtered out during confirmation\n")
    }

    return final
}

func randPath() string {
    var b [8]byte
    _, _ = crand.Read(b[:])
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
    count := 0 // number of eligible URLs seen
    mrand.Seed(time.Now().UnixNano())
    for sc.Scan() {
        raw := strings.TrimSpace(sc.Text())
        if raw == "" { continue }
        u, perr := url.Parse(raw)
        if perr != nil || u.Scheme == "" || u.Host == "" { continue }
        p := u.Path
        if p == "" || p == "/" { continue }

        count++
        if len(out) < k {
            out = append(out, raw)
            continue
        }
        // Reservoir sampling: pick index in [0, count), replace if < k
        j := mrand.Intn(count)
        if j < k {
            out[j] = raw
        }
    }
    return out
}
