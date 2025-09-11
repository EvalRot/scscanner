package scpt

import (
    "context"
    "fmt"
    "math/rand"
    "net/url"
    "strings"
    "sync"
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

// Payloads returns the SCPT-specific payload source. Keeping a dedicated
// instance allows other modules to use their own lists independently.
func (Module) Payloads() *payload.Source {
    // For now, reuse the default list. This can be tuned for SCPT later
    // without affecting other modules.
    return payload.NewDefault()
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
    fmt.Printf("[scpt] scanning %s%s\n", t.BaseURL, t.Path)

    // Pull the module-specific payload list
    payloads := deps.Payloads.Items()
    if len(payloads) == 0 {
        return nil
    }

    // Normalize current path and compute parent and baselines once per target
    path := t.Path
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
    nonexistent := strings.TrimSuffix(back, "/") + "/gachimuchicheburek"
    nonResp, err := deps.Client.Do(t.BaseURL, nonexistent)
    if err != nil {
        return nil
    }

    // Sequential per-payload scanning (engine handles target-level concurrency)
    var mu sync.Mutex
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

            // Detection logic: differ from parent and from parent's non-existent
            statusDiff := (resp.StatusCode != backResp.StatusCode) && (resp.StatusCode != nonResp.StatusCode)
            serverDiff := (resp.Server != backResp.Server) && (resp.Server != nonResp.Server)
            contentTypeDiff := (resp.ContentType != backResp.ContentType) && (resp.ContentType != nonResp.ContentType)
            notes := make([]string, 0, 3)
            if statusDiff { notes = append(notes, "Status code differs (vs parent & non-existent)") }
            if serverDiff { notes = append(notes, "Server header differs (vs parent & non-existent)") }
            if contentTypeDiff { notes = append(notes, "Content-Type differs (vs parent & non-existent)") }
            if statusDiff || serverDiff || contentTypeDiff {
                emitFinding(deps, t.BaseURL, path, p, resp, statusDiff, serverDiff, contentTypeDiff, notes, &mu)
            }
            break
        }
    }
    return nil
}

func emitFinding(deps engine.Deps, baseURL, path, payload string, resp *httpx.Response, statusDiff, serverDiff, contentTypeDiff bool, notes []string, mu *sync.Mutex) {
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
    mu.Lock()
    _ = deps.Sink.Write(f)
    mu.Unlock()
}

// Note: target iteration and baseline building happens in the engine for per-URL streaming.
