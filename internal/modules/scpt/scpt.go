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
    threads := deps.Opts.Threads
    if threads <= 0 { threads = 1 }

    // Prepare dummy responses for each payload using a never-existing marker
    dummyMarker := "/gachimuchicheburek/"
    dummyPayloads := deps.Payloads.BuildTraversal(dummyMarker)
    dummyResponses := make([]*httpx.Response, 0, len(dummyPayloads))
    filteredPayloads := make([]string, 0, len(dummyPayloads))
    for i, p := range dummyPayloads {
        dr, derr := deps.Client.Do(t.BaseURL, p)
        if derr != nil { continue }
        // Skip payloads that the app consistently blocks with 403 while base is allowed
        if dr.StatusCode != 403 || base.StatusCode == 403 {
            dummyResponses = append(dummyResponses, dr)
            filteredPayloads = append(filteredPayloads, deps.Payloads.Items()[i])
        }
    }
    if len(dummyResponses) == 0 { return nil }

    jobs := make(chan string, threads)
    var wg sync.WaitGroup
    mu := sync.Mutex{}
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            worker(ctx, deps, t.BaseURL, base, dummyResponses, filteredPayloads, jobs, &mu)
        }()
    }
    // Normalize path for traversal attempts
    path := t.Path
    if path != "" && !strings.HasSuffix(path, "/") { path = path + "/" }
    jobs <- path
    close(jobs)
    wg.Wait()
    return nil
}

func worker(ctx context.Context, deps engine.Deps, baseURL string, baseResp *httpx.Response, dummyResponses []*httpx.Response, dummyPayloads []string, jobs <-chan string, mu *sync.Mutex) {
    for raw := range jobs {
        select {
        case <-ctx.Done():
            return
        default:
        }
        u, _ := url.Parse(raw)
        path := u.Path
        back := helper.OneStepBackPath(path)
        dummyBase := back + "gachimuchicheburek/"
        nonexistent := path + "gachimuchicheburek/"

        nonResp, err := deps.Client.Do(baseURL, nonexistent)
        if err != nil {
            continue
        }

        var backResp *httpx.Response
        if back == "/" || strings.TrimSpace(back) == "" {
            backResp = baseResp
        } else {
            b, berr := deps.Client.Do(baseURL, back)
            if berr != nil {
                continue
            }
            backResp = b
        }

        // Build traversal paths for this path, reusing filtered dummy payloads
        travPaths := make([]string, 0, len(dummyPayloads))
        for _, pay := range dummyPayloads {
            travPaths = append(travPaths, path+pay)
        }

        for i := range travPaths {
            // Per-payload dummy baseline if URLsFile mode
            var dummyResp *httpx.Response
            if deps.Opts.URLsFile {
                pr := dummyBase + dummyPayloads[i]
                dr, derr := deps.Client.Do(baseURL, pr)
                if derr != nil {
                    continue
                }
                dummyResp = dr
            } else {
                dummyResp = dummyResponses[i%len(dummyResponses)]
            }

            retries := deps.Opts.Retry
            for attempt := 0; attempt <= retries; attempt++ {
                resp, err := deps.Client.Do(baseURL, travPaths[i])
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

                // Module-specific detection logic
                statusDiff := (resp.StatusCode != backResp.StatusCode) && (resp.StatusCode != dummyResp.StatusCode) && (resp.StatusCode != nonResp.StatusCode)
                serverDiff := (resp.Server != backResp.Server) && (resp.Server != dummyResp.Server) && (resp.Server != nonResp.Server)
                contentTypeDiff := (resp.ContentType != backResp.ContentType) && (resp.ContentType != dummyResp.ContentType) && (resp.ContentType != nonResp.ContentType)
                notes := make([]string, 0, 3)
                if statusDiff { notes = append(notes, "Status code differs") }
                if serverDiff { notes = append(notes, "Server header differs") }
                if contentTypeDiff { notes = append(notes, "Content-Type header differs") }
                if statusDiff || serverDiff || contentTypeDiff {
                    emitFinding(deps, baseURL, path, dummyPayloads[i%len(dummyPayloads)], resp, statusDiff, serverDiff, contentTypeDiff, notes, mu)
                }
                break
            }
        }
    }
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
