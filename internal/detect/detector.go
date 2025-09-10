package detect

// Package detect provides low-level helpers for detection heuristics that modules can use.
// Keep this package lightweight and generic; module-specific logic should live in each module.

// DiffInt returns true if v differs from all reference values.
func DiffInt(v int, refs ...int) bool {
    for _, r := range refs {
        if v == r {
            return false
        }
    }
    return true
}

// DiffStr returns true if v differs from all reference values.
func DiffStr(v string, refs ...string) bool {
    for _, r := range refs {
        if v == r {
            return false
        }
    }
    return true
}
