# Architecture Overview

This document summarizes the current layered architecture of the scanner and how modules (checks) are executed per URL with a shared baseline response.

## Layers
- CLI (main.go)
  - Parses flags, builds `config.Options`, constructs shared services, and starts the engine.
- Config (`internal/config`)
  - Holds `Options` and helpers such as `BuildBaseURL()`.
- HTTP (`internal/httpx`)
  - Thin wrapper over `net/http` that preserves raw paths via `URL.Opaque`, supports TLS/proxy/redirect policy.
- Payloads (`internal/payload`)
  - Provides traversal payload sources and helpers to build candidate paths. Modules may supply their own payload source.
- Output (`internal/output`)
  - Sinks for findings (Stdout, JSONL). `Finding` includes a `Module` field.
- Detect Utilities (`internal/detect`)
  - Small, generic helpers for detection heuristics (e.g., value difference checks). Module-specific logic stays inside modules.
- Engine (`internal/engine`)
  - Orchestrates per-URL streaming, builds a canonical baseline per URL, supports optional per-module preprocessing, and runs enabled modules.
- Modules (`internal/modules/<name>`)
  - Self-contained checks implementing the `Module` interface. Example: `scpt` (Secondary Context Path Traversal).

## Engine and Module Contracts

```go
// Deps are shared services/modules receive from the engine
type Deps struct {
    Opts     *config.Options
    Client   *httpx.Client
    Payloads *payload.Source
    Sink     output.Sink
}

// Target represents a single URL to scan
type Target struct {
    BaseURL string // e.g., https://example.com
    Path    string // raw path, expected to start with "/"
}

// Module API: each module processes one Target using the provided base response
type Module interface {
    Name() string
    Process(ctx context.Context, deps Deps, t Target, base *httpx.Response) error
}

// Optional: modules can adjust the Target and/or provide a module-specific
// baseline before Process is invoked.
type Preprocessor interface {
    Preprocess(ctx context.Context, deps Deps, t Target, base *httpx.Response) (Target, *httpx.Response, error)
}

// Optional: modules can provide their own payload source.
type PayloadProvider interface {
    Payloads() *payload.Source
}
```

### Per‑URL Streaming with Baselines
- The engine reads the target list in a streaming fashion (line by line) via `iterateTargets`.
- For each `Target`, the engine:
  1) Normalizes the path (preserves query from URL lists), 2) performs one canonical base request using `httpx.Client.Do(baseURL, path)`, 3) for each module, optionally runs `Preprocess` to adjust the Target and/or baseline, and 4) calls `Process`.
- Modules typically reuse the engine baseline; modules that implement `Preprocess` may substitute a module-specific baseline.
- After all modules finish for the current target, baselines are discarded and the engine proceeds to the next target.

## HTTP Client (`internal/httpx`)
- Preserves raw traversal sequences by setting `Request.URL.Opaque`.
- Configurable redirect policy (via options), timeouts, TLS validation (honors `NoTLSValidation`), and proxy.
- Intended to evolve to support per-request options for modules that need different policies (e.g., redirect on/off).

## Payloads (`internal/payload`)
- `Source` provides ordered payloads (from stealth to aggressive) and `BuildTraversal(path)` to generate candidate URLs for checks like SCPT.

## Output (`internal/output`)
- `Finding` is a structured record including `Module`, `Host`, `Path`, `Payload`, `Signals`, `Notes`, `Status`, `Server`, `ContentType`, and timestamp.
- `JSONLSink` writes one JSON object per line per host. `StdoutSink` prints compact text.

## SCPT Module (`internal/modules/scpt`)
- Implements Secondary Context Path Traversal as a module.
- `Preprocess`: strips GET parameters from the path and rebuilds a baseline for the stripped path (SCPT only mutates the path segment).
- `Process` behavior for a single `Target`:
  1) Receives the engine-provided base response (baseline for comparisons).
  2) Builds additional per-target baselines as needed: one-step-back, dummy, and nonexistent paths.
  3) Generates traversal payload candidates using `payload.Source`.
  4) Sends traversal requests and compares them against the baselines using simple heuristics (status/server/content-type differences).
  5) Emits findings to the configured sink with `Module = "scpt"`.

## CLI and Modules
- The SCPT module can be toggled with the `--scpt` flag (boolean). Defaults to enabled.
- Future modules can add similar flags and be appended to the engine’s `Modules` slice in `main.go`.

## Extending with New Modules
- Create a new module package under `internal/modules/<name>` that implements `Module`.
- Reuse `Deps` (HTTP, Payloads, Output) and accept the per-URL base response from the engine.
- Implement module-specific detection logic inside `Process`.
- Register the module in `main.go` by adding it (and its flag) to the engine’s `Modules` slice.

## Future Enhancements
- Per-request HTTP options (redirects, header overrides) to isolate module behavior.
- Optional in-memory request de-duplication per target to avoid repeated identical requests across modules.
- Rate limiting / backoff as a shared engine service.
- CLI `--modules` list flag to select multiple modules by name.
