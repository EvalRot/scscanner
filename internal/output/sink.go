package output

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "time"
    "sync"
)

// Finding is a structured record of a single detection event.
type Finding struct {
    Module      string            `json:"module"`
    Timestamp   time.Time         `json:"ts"`
    Host        string            `json:"host"`
    Path        string            `json:"path"`
    Payload     string            `json:"payload"`
    URL         string            `json:"url"`
    Signals     map[string]bool   `json:"signals"`
    Notes       []string          `json:"notes"`
    Status      int               `json:"status"`
    Server      string            `json:"server"`
    ContentType string            `json:"content_type"`
}

// Sink is a destination for findings (stdout, file, JSONL, etc.).
type Sink interface {
    Write(*Finding) error
}

// SafeSink wraps another Sink and serializes concurrent Write calls.
type SafeSink struct {
    mu    sync.Mutex
    Inner Sink
}

// NewSafe returns a thread-safe wrapper around the provided sink.
func NewSafe(inner Sink) *SafeSink { return &SafeSink{Inner: inner} }

func (s *SafeSink) Write(f *Finding) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.Inner.Write(f)
}

// StdoutSink prints findings to stdout in a compact textual form.
type StdoutSink struct{}

func (s StdoutSink) Write(f *Finding) error {
    fmt.Printf("[+] %s %s payload=%q status=%d signals=%v\n", f.Host, f.Path, f.Payload, f.Status, f.Signals)
    return nil
}

// JSONLSink writes findings to a JSONL file per host inside OutputDir.
type JSONLSink struct{
    OutputDir string
}

func (s JSONLSink) Write(f *Finding) error {
    if s.OutputDir == "" || s.OutputDir == "no.no" {
        // If no directory provided, fallback to stdout
        return StdoutSink{}.Write(f)
    }
    if err := os.MkdirAll(s.OutputDir, 0o755); err != nil {
        return err
    }
    filename := filepath.Join(s.OutputDir, safeFilename(f.Host)+".jsonl")
    fp, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
    if err != nil {
        return err
    }
    defer fp.Close()
    enc := json.NewEncoder(fp)
    return enc.Encode(f)
}

func safeFilename(host string) string {
    // A very small sanitizer for filenames based on host.
    b := make([]rune, 0, len(host))
    for _, r := range host {
        switch r {
        case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
            b = append(b, '_')
        default:
            b = append(b, r)
        }
    }
    return string(b)
}
