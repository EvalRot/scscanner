package scpt

import (
    "bufio"
    _ "embed"
    "strings"

    "pohek/internal/engine"
)

//go:embed payloads.txt
var embeddedPayloads string

// defaultPayloads parses the embedded payload file and returns non-empty lines.
func defaultPayloads() []string {
    out := make([]string, 0, 16)
    sc := bufio.NewScanner(strings.NewReader(embeddedPayloads))
    for sc.Scan() {
        s := strings.TrimSpace(sc.Text())
        if s == "" || strings.HasPrefix(s, "#") { // allow comments
            continue
        }
        out = append(out, s)
    }
    return out
}

// modulePayloads returns the payload list to use for this module.
// If deps provides an override (after precheck), use it; otherwise, use embedded defaults.
func modulePayloads(deps engine.Deps) []string {
    if deps.Payloads != nil {
        items := deps.Payloads.Items()
        if len(items) > 0 {
            cp := make([]string, len(items))
            copy(cp, items)
            return cp
        }
    }
    return defaultPayloads()
}