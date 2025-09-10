package detect

import "pohek/internal/httpx"

// Baselines represents a set of baseline responses for comparison.
// Keeping multiple baselines reduces false positives in secondary context traversal.
type Baselines struct {
    Normal      *httpx.Response // the untouched path
    OneStepBack *httpx.Response // parent directory (or root)
    Dummy       *httpx.Response // same pattern but on a non-existent sibling
    Nonexistent *httpx.Response // clearly non-existent path under the target path
}

// Signals summarizes detection evidence gathered during evaluation.
type Signals struct {
    StatusDiff     bool
    ServerDiff     bool
    ContentTypeDiff bool
    Notes          []string
}

// Detector is the interface for deciding whether a given traversal response looks suspicious.
type Detector interface {
    Evaluate(b Baselines, cand *httpx.Response, url string) (Signals, bool)
}

// BasicDetector implements simple heuristics based on status code and headers differences.
// It mirrors the project’s previous logic while keeping the detector isolated and testable.
type BasicDetector struct{}

func (d BasicDetector) Evaluate(b Baselines, cand *httpx.Response, url string) (Signals, bool) {
    sig := Signals{}
    // Compare against multiple baselines to reduce noise.
    if diffInt(cand.StatusCode, b.OneStepBack.StatusCode, b.Dummy.StatusCode, b.Nonexistent.StatusCode) {
        sig.StatusDiff = true
        sig.Notes = append(sig.Notes, "Status code differs")
    }
    if diffStr(cand.Server, b.OneStepBack.Server, b.Dummy.Server, b.Nonexistent.Server) {
        sig.ServerDiff = true
        sig.Notes = append(sig.Notes, "Server header differs")
    }
    if diffStr(cand.ContentType, b.OneStepBack.ContentType, b.Dummy.ContentType, b.Nonexistent.ContentType) {
        sig.ContentTypeDiff = true
        sig.Notes = append(sig.Notes, "Content-Type header differs")
    }
    positive := sig.StatusDiff || sig.ServerDiff || sig.ContentTypeDiff
    return sig, positive
}

func diffInt(v int, refs ...int) bool {
    for _, r := range refs {
        if v == r {
            return false
        }
    }
    return true
}

func diffStr(v string, refs ...string) bool {
    for _, r := range refs {
        if v == r {
            return false
        }
    }
    return true
}

