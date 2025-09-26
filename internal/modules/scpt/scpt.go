package scpt

import (
    "context"
    "fmt"
    "math/rand"
    "net/url"
    "strings"
    "time"

	"pohek/helper"
	"pohek/internal/engine"
	"pohek/internal/httpx"
	"pohek/internal/output"
	"pohek/internal/payload"
)

// Module implements secondary context path traversal scanning as a pluggable module.
// It reuses shared dependencies (HTTP client, payload source, detector, sink) passed via engine.Deps.
type Module struct{}

func (Module) Name() string { return "scpt" }

// DedupKey implements engine.DedupKeyer. SCPT ignores query and fragment and
// operates on parent path context, so dedup on normalized path only.
func (Module) DedupKey(t engine.Target) string {
    p := t.Path
    if i := strings.IndexByte(p, '?'); i >= 0 { p = p[:i] }
    if j := strings.IndexByte(p, '#'); j >= 0 { p = p[:j] }
    if p == "" { p = "/" }
    if !strings.HasPrefix(p, "/") { p = "/" + p }
    if !strings.HasSuffix(p, "/") { p = p + "/" }
    return t.BaseURL + " " + p
}

// Payloads returns the SCPT-specific payload source. Keeping a dedicated
// instance allows other modules to use their own lists independently.
func (Module) Payloads() *payload.Source {
    // Load payloads from the module's embedded file
    return payload.NewFrom(defaultPayloads())
}

// Preprocess removes GET parameters from the path, since SCPT only mutates
// the URL path segment. It also rebuilds a baseline for the stripped path so
// subsequent comparisons use the correct reference.
func (Module) Preprocess(ctx context.Context, deps engine.Deps, t engine.Target, base *httpx.Response) (engine.Target, *httpx.Response, error) {
    raw := t.Path
    if raw == "" {
        return t, base, nil
    }
    // Extract path only; ignore query and fragment
    u, err := url.Parse(raw)
    var cleaned string
    if err == nil {
        cleaned = u.Path
    } else {
        cleaned = raw
        if i := strings.Index(cleaned, "?"); i >= 0 { cleaned = cleaned[:i] }
        if j := strings.Index(cleaned, "#"); j >= 0 { cleaned = cleaned[:j] }
    }
    if cleaned == "" { cleaned = "/" }
    if !strings.HasPrefix(cleaned, "/") { cleaned = "/" + cleaned }
    if cleaned == raw {
        return t, base, nil
    }
    nb, nerr := deps.Client.Do(t.BaseURL, cleaned)
    if nerr != nil {
        // fall back to original baseline on error
        return engine.Target{BaseURL: t.BaseURL, Path: cleaned}, base, nil
    }
    return engine.Target{BaseURL: t.BaseURL, Path: cleaned}, nb, nil
}

// Run performs SCT scanning for targets derived from the provided options and wordlist.
// It builds multiple baselines (root/parent/dummy/nonexistent) to reduce false positives
// and performs module-specific detection heuristics.
// Process runs SCT payloads for a single target, using the provided base response as baseline.
func (Module) Process(ctx context.Context, deps engine.Deps, t engine.Target, base *httpx.Response) error {
    // Pull payloads: prefer override from deps (after precheck),
    // otherwise use the module's embedded defaults.
    var payloads []string
    if deps.Payloads != nil {
        payloads = deps.Payloads.Items()
    }
    if len(payloads) == 0 {
        payloads = defaultPayloads()
    }
    if len(payloads) == 0 {
        return nil
    }

    // Normalize current path and compute parent and baselines once per target
    path := t.Path
    // If path is root, traversal above root is not applicable; skip.
    if path == "/" || strings.TrimSpace(path) == "" {
        fmt.Printf("[scpt] skipping root path for %s (no parent context)\n", t.BaseURL)
        return nil
    }
    if path != "" && !strings.HasSuffix(path, "/") {
        path = path + "/"
    }
    back := helper.OneStepBackPath(path)

    // Parent baseline
    var backResp *httpx.Response
    if back == "/" || strings.TrimSpace(back) == "" {
        backResp = base
    } else {
        b, berr := deps.Client.Do(t.BaseURL, back)
        if berr != nil {
            return nil
        }
        backResp = b
    }

    // Non-existent under parent context
    nonexistent := strings.TrimSuffix(path, "/") + "/gachimuchicheburek"
    nonResp, err := deps.Client.Do(t.BaseURL, nonexistent)
    if err != nil {
        return nil
    }

    // Sequential per-payload scanning (engine handles target-level concurrency)
    for _, p := range payloads {
        travPath := path + p
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }
        retries := deps.Opts.Retry
        for attempt := 0; attempt <= retries; attempt++ {
            resp, err := deps.Client.Do(t.BaseURL, travPath)
            if err != nil {
                if attempt < retries {
                    continue
                }
                // Backoff a little before moving on
                rand.Seed(time.Now().UnixNano())
                n := rand.Intn(4) + 2 // 2..5 sec
                time.Sleep(time.Duration(n) * time.Second)
                break
            }

            // 429-aware backoff: honor Retry-After if present; else exponential with jitter.
            if resp.StatusCode == 429 {
                if attempt < retries {
                    if resp.RetryAfter > 0 {
                        time.Sleep(resp.RetryAfter)
                    } else {
                        // exponential backoff: base 1s << attempt, capped to 8s, plus jitter 0-300ms
                        base := 1 << attempt
                        if base > 8 { base = 8 }
                        d := time.Duration(base) * time.Second
                        rand.Seed(time.Now().UnixNano())
                        d += time.Duration(rand.Intn(300)) * time.Millisecond
                        time.Sleep(d)
                    }
                    continue
                }
                // No more retries; treat as non-detection and move on
                break
            }

            // Detection logic: differ from parent and from parent's non-existent
            statusDiff := (resp.StatusCode != backResp.StatusCode) && (resp.StatusCode != nonResp.StatusCode)
            serverDiff := (resp.Server != backResp.Server) && (resp.Server != nonResp.Server)
            contentTypeDiff := (resp.ContentType != backResp.ContentType) && (resp.ContentType != nonResp.ContentType)
            notes := make([]string, 0, 3)
            if statusDiff { notes = append(notes, "Status code differs (vs parent & non-existent)") }
            if serverDiff { notes = append(notes, "Server header differs (vs parent & non-existent)") }
            if contentTypeDiff { notes = append(notes, "Content-Type differs (vs parent & non-existent)") }
            if statusDiff || serverDiff || contentTypeDiff {
                emitFinding(deps, t.BaseURL, path, p, resp, statusDiff, serverDiff, contentTypeDiff, notes)
            }
            break
        }
    }
    return nil
}

func emitFinding(deps engine.Deps, baseURL, path, payload string, resp *httpx.Response, statusDiff, serverDiff, contentTypeDiff bool, notes []string) {
    f := &output.Finding{
        Module:      "scpt",
        Timestamp:   time.Now(),
        Host:        baseURL,
        Path:        path,
        Payload:     payload,
        URL:         resp.RequestURL,
        Signals:     map[string]bool{"status": statusDiff, "server": serverDiff, "content_type": contentTypeDiff},
        Notes:       notes,
        Status:      resp.StatusCode,
        Server:      resp.Server,
        ContentType: resp.ContentType,
    }
    _ = deps.Sink.Write(f)
}

// Note: target iteration and baseline building happens in the engine for per-URL streaming.
