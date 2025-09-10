package engine

import (
    "bufio"
    "context"
    "net/url"
    "os"
    "strings"

    "pohek/internal/config"
    "pohek/internal/httpx"
    "pohek/internal/output"
    "pohek/internal/payload"
)

// Deps aggregates shared services and configuration to be provided to modules.
// Keeping them centralized avoids tight coupling between modules and concrete implementations.
type Deps struct {
    Opts     *config.Options
    Client   *httpx.Client
    Payloads *payload.Source
    Sink     output.Sink
}

// Target represents a single URL to scan, split into base host URL and raw path.
// BaseURL must be an absolute URL with scheme and host (e.g., https://example.com)
// Path is the raw path to request (should start with "/").
type Target struct {
    BaseURL string
    Path    string
}

// Module is a self-contained check (e.g., SCT, Host header, Smuggling).
// It receives shared dependencies via Deps and reports findings via the Sink.
type Module interface {
    // Name returns a short, stable identifier of the module (e.g., "sct").
    Name() string
    // Process runs the module's checks for a single target using the provided baseline response.
    Process(ctx context.Context, deps Deps, t Target, base *httpx.Response) error
}

// Engine orchestrates execution of one or more modules.
// It does not know about module internals; it only sequences them with shared dependencies.
type Engine struct {
    Deps    Deps
    Modules []Module
}

// Run streams targets one-by-one and reuses a single base response per target across modules.
func (e *Engine) Run(ctx context.Context) error {
    return e.iterateTargets(ctx, func(t Target) error {
        p := t.Path
        if p != "" && !strings.HasPrefix(p, "/") {
            p = "/" + p
        }
        // Build baseline once per target
        base, err := e.Deps.Client.Do(t.BaseURL, p)
        if err != nil {
            // skip target on error
            return nil
        }
        for _, m := range e.Modules {
            _ = m.Process(ctx, e.Deps, Target{BaseURL: t.BaseURL, Path: p}, base)
        }
        return nil
    })
}

// iterateTargets builds targets from the configured wordlist in a streaming manner
// and calls fn for each target. It avoids storing all targets in memory.
func (e *Engine) iterateTargets(ctx context.Context, fn func(Target) error) error {
    wl, err := os.Open(e.Deps.Opts.Wordlist)
    if err != nil { return err }
    defer wl.Close()

    sc := bufio.NewScanner(wl)
    if e.Deps.Opts.URLsFile {
        for sc.Scan() {
            select { case <-ctx.Done(): return ctx.Err(); default: }
            raw := strings.TrimSpace(sc.Text())
            if raw == "" { continue }
            u, err := url.Parse(raw)
            if err != nil || u.Scheme == "" || u.Host == "" { continue }
            base := u.Scheme + "://" + u.Host
            if err := fn(Target{BaseURL: base, Path: u.Path}); err != nil { _ = err }
        }
        return sc.Err()
    }

    base, err := e.Deps.Opts.BuildBaseURL()
    if err != nil { return err }
    for sc.Scan() {
        select { case <-ctx.Done(): return ctx.Err(); default: }
        p := strings.TrimSpace(sc.Text())
        if p == "" { continue }
        if err := fn(Target{BaseURL: base, Path: p}); err != nil { _ = err }
    }
    return sc.Err()
}
