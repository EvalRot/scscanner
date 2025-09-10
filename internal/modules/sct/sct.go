package sct

import (
    "bufio"
    "context"
    "fmt"
    "math/rand"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "pohek/helper"
    "pohek/internal/engine"
    "pohek/internal/httpx"
    "pohek/internal/output"
)

// Module implements secondary context path traversal scanning as a pluggable module.
// It reuses shared dependencies (HTTP client, payload source, detector, sink) passed via engine.Deps.
type Module struct{}

func (Module) Name() string { return "sct" }

// Run performs SCT scanning for targets derived from the provided options and wordlist.
// It builds multiple baselines (root/parent/dummy/nonexistent) to reduce false positives
// and performs module-specific detection heuristics.
func (Module) Run(ctx context.Context, deps engine.Deps) error {
    // Build target map: host -> paths
    targets, err := loadTargets(deps)
    if err != nil {
        return err
    }

    // Prepare global concurrency
    threads := deps.Opts.Threads
    if threads <= 0 {
        threads = 1
    }

    for host, paths := range targets {
        fmt.Printf("Running scan for %s: %d paths\n", host, len(paths))

        // Root baseline
        rootResp, err := deps.Client.Do(host, "")
        if err != nil {
            fmt.Printf("[!] Cannot reach %s: %v\n", host, err)
            continue
        }

        // Precompute dummy responses for each payload using a never-existing marker
        dummyMarker := "/gachimuchicheburek/"
        dummyPayloads := deps.Payloads.BuildTraversal(dummyMarker)
        dummyResponses := make([]*httpx.Response, 0, len(dummyPayloads))
        filteredPayloads := make([]string, 0, len(dummyPayloads))
        deps.Client.SetRedirects(false)
        for i, p := range dummyPayloads {
            dr, derr := deps.Client.Do(host, p)
            if derr != nil {
                continue
            }
            // Skip payloads that the app consistently blocks with 403 while root is allowed
            if dr.StatusCode != 403 || rootResp.StatusCode == 403 {
                dummyResponses = append(dummyResponses, dr)
                filteredPayloads = append(filteredPayloads, deps.Payloads.Items()[i])
            }
        }
        if len(dummyResponses) == 0 {
            fmt.Println("[!] Target appears to block traversal completely; skipping host")
            continue
        }

        // Worker pool
        jobs := make(chan string, threads)
        var wg sync.WaitGroup
        mu := sync.Mutex{}

        for i := 0; i < threads; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                worker(ctx, deps, host, rootResp, dummyResponses, filteredPayloads, jobs, &mu)
            }()
        }
        for _, p := range paths {
            if p == "" {
                continue
            }
            path := p
            if !strings.HasPrefix(path, "/") {
                path = "/" + path
            }
            if !strings.HasSuffix(path, "/") {
                path = path + "/"
            }
            jobs <- path
        }
        close(jobs)
        wg.Wait()
    }

    return nil
}

func worker(ctx context.Context, deps engine.Deps, baseURL string, rootResp *httpx.Response, dummyResponses []*httpx.Response, dummyPayloads []string, jobs <-chan string, mu *sync.Mutex) {
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
            backResp = rootResp
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
        Module:      "sct",
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

// loadTargets reads the wordlist and returns a map of base host URL -> list of paths.
func loadTargets(deps engine.Deps) (map[string][]string, error) {
    targets := make(map[string][]string)
    file, err := os.Open(deps.Opts.Wordlist)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    if deps.Opts.URLsFile {
        sc := bufio.NewScanner(file)
        for sc.Scan() {
            raw := strings.TrimSpace(sc.Text())
            if raw == "" {
                continue
            }
            u, err := url.Parse(raw)
            if err != nil {
                continue
            }
            host := u.Scheme + "://" + u.Host
            targets[host] = append(targets[host], u.Path)
        }
        if err := sc.Err(); err != nil {
            return nil, err
        }
        return targets, nil
    }

    // Single base host with paths from wordlist
    baseURL, err := deps.Opts.BuildBaseURL()
    if err != nil {
        return nil, err
    }
    sc := bufio.NewScanner(file)
    for sc.Scan() {
        p := strings.TrimSpace(sc.Text())
        if p == "" {
            continue
        }
        targets[baseURL] = append(targets[baseURL], p)
    }
    if err := sc.Err(); err != nil {
        return nil, err
    }
    return targets, nil
}
