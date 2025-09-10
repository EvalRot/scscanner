package scanner

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
    "pohek/internal/config"
    "pohek/internal/detect"
    "pohek/internal/httpx"
    "pohek/internal/output"
    "pohek/internal/payload"
)

// Runner orchestrates the scan using dependencies injected from higher layers.
type Runner struct {
    Opts     *config.Options
    Client   *httpx.Client
    Payloads *payload.Source
    Detector detect.Detector
    Sink     output.Sink

    // internal state
    mu        sync.Mutex
}

// Run executes the scan. It supports two input modes:
// 1) URLsFile=false: wordlist is a file with paths to test against a single Hostname.
// 2) URLsFile=true: wordlist is a file with full URLs (scheme://host/path), grouped by host.
func (r *Runner) Run(ctx context.Context) error {
    baseURL, err := r.Opts.BuildBaseURL()
    if err != nil {
        return err
    }

    // Build target map: host -> paths
    targets, err := r.loadTargets()
    if err != nil {
        return err
    }

    threads := r.Opts.Threads
    if threads <= 0 { threads = 1 }

    for host, paths := range targets {
        fmt.Printf("Running scan for %s: %d paths\n", host, len(paths))

        // Adjust base URL when iterating multiple hosts (URLsFile mode)
        bURL := baseURL
        if r.Opts.URLsFile {
            // host includes scheme already in URLsFile mode
            bURL = host
        }

        // Prepare baselines that are constant across many paths
        // Root baseline
        rootResp, err := r.Client.Do(bURL, "")
        if err != nil {
            fmt.Printf("[!] Cannot reach %s: %v\n", bURL, err)
            continue
        }

        // Precompute dummy responses for each payload using a never-existing marker under one-step-back path
        dummyMarker := "/gachimuchicheburek/"
        dummyPayloads := r.Payloads.BuildTraversal(dummyMarker)
        dummyResponses := make([]*httpx.Response, 0, len(dummyPayloads))
        dummyPayloadFilter := make([]string, 0, len(dummyPayloads))
        // Disable redirects temporarily to keep behavior consistent with baseline comparison
        r.Client.SetRedirects(false)
        for i, p := range dummyPayloads {
            dr, derr := r.Client.Do(bURL, p)
            if derr != nil {
                continue
            }
            // Filter out payloads blocked at proxy layer returning 403 consistently
            if dr.StatusCode != 403 || rootResp.StatusCode == 403 {
                dummyResponses = append(dummyResponses, dr)
                dummyPayloadFilter = append(dummyPayloadFilter, r.Payloads.Items()[i])
            }
        }
        if len(dummyResponses) == 0 {
            fmt.Println("[!] Target appears to block traversal completely; skipping host")
            continue
        }

        // Make a worker pool
        jobs := make(chan string, threads)
        var wg sync.WaitGroup
        for i := 0; i < threads; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                r.worker(ctx, bURL, rootResp, dummyResponses, dummyPayloadFilter, jobs)
            }()
        }
        for _, p := range paths {
            if p == "" { continue }
            path := p
            if !strings.HasPrefix(path, "/") { path = "/" + path }
            if !strings.HasSuffix(path, "/") { path = path + "/" }
            jobs <- path
        }
        close(jobs)
        wg.Wait()
    }

    return nil
}

func (r *Runner) worker(ctx context.Context, baseURL string, rootResp *httpx.Response, dummyResponses []*httpx.Response, dummyPayloads []string, jobs <-chan string) {
    for raw := range jobs {
        select { case <-ctx.Done(): return; default: }
        u, _ := url.Parse(raw)
        path := u.Path
        back := helper.OneStepBackPath(path)
        dummyBase := back + "gachimuchicheburek/"
        nonexistent := path + "gachimuchicheburek/"

        nonResp, err := r.Client.Do(baseURL, nonexistent)
        if err != nil { continue }

        var backResp *httpx.Response
        if back == "/" || strings.TrimSpace(back) == "" {
            backResp = rootResp
        } else {
            b, berr := r.Client.Do(baseURL, back)
            if berr != nil { continue }
            backResp = b
        }

        // Build traversal paths for this path
        // Note: we reuse filtered dummy payloads to stay in sync with allowed traversal patterns.
        travPaths := make([]string, 0, len(dummyPayloads))
        for _, pay := range dummyPayloads {
            travPaths = append(travPaths, path+pay)
        }

        for i := range travPaths {
            // Prepare per-payload dummy baselines if URLsFile mode (keep behavior closer to legacy)
            var dummyResp *httpx.Response
            if r.Opts.URLsFile {
                pr := dummyBase + dummyPayloads[i]
                dr, derr := r.Client.Do(baseURL, pr)
                if derr != nil { continue }
                dummyResp = dr
            } else {
                dummyResp = dummyResponses[i%len(dummyResponses)]
            }

            retries := r.Opts.Retry
            for attempt := 0; attempt <= retries; attempt++ {
                resp, err := r.Client.Do(baseURL, travPaths[i])
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

                bl := detect.Baselines{Normal: rootResp, OneStepBack: backResp, Dummy: dummyResp, Nonexistent: nonResp}
                sig, pos := r.Detector.Evaluate(bl, resp, travPaths[i])
                if pos {
                    r.emitFinding(baseURL, path, dummyPayloads[i%len(dummyPayloads)], resp, sig)
                }
                break
            }
        }
    }
}

func (r *Runner) emitFinding(baseURL, path, payload string, resp *httpx.Response, sig detect.Signals) {
    f := &output.Finding{
        Timestamp:   time.Now(),
        Host:        baseURL,
        Path:        path,
        Payload:     payload,
        URL:         resp.RequestURL,
        Signals:     map[string]bool{"status": sig.StatusDiff, "server": sig.ServerDiff, "content_type": sig.ContentTypeDiff},
        Notes:       sig.Notes,
        Status:      resp.StatusCode,
        Server:      resp.Server,
        ContentType: resp.ContentType,
    }
    r.mu.Lock()
    _ = r.Sink.Write(f)
    r.mu.Unlock()
}

// loadTargets reads the wordlist and returns a map of base host URL -> list of paths.
func (r *Runner) loadTargets() (map[string][]string, error) {
    targets := make(map[string][]string)
    file, err := os.Open(r.Opts.Wordlist)
    if err != nil { return nil, err }
    defer file.Close()

    if r.Opts.URLsFile {
        sc := bufio.NewScanner(file)
        for sc.Scan() {
            raw := strings.TrimSpace(sc.Text())
            if raw == "" { continue }
            u, err := url.Parse(raw)
            if err != nil { continue }
            host := u.Scheme + "://" + u.Host
            targets[host] = append(targets[host], u.Path)
        }
        if err := sc.Err(); err != nil { return nil, err }
        return targets, nil
    }

    // Single base host with paths from wordlist
    baseURL, err := r.Opts.BuildBaseURL()
    if err != nil { return nil, err }
    sc := bufio.NewScanner(file)
    for sc.Scan() {
        p := strings.TrimSpace(sc.Text())
        if p == "" { continue }
        targets[baseURL] = append(targets[baseURL], p)
    }
    if err := sc.Err(); err != nil { return nil, err }
    return targets, nil
}

