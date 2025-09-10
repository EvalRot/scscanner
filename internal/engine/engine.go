package engine

import (
    "context"

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

// Module is a self-contained check (e.g., SCT, Host header, Smuggling).
// It receives shared dependencies via Deps and reports findings via the Sink.
type Module interface {
    // Name returns a short, stable identifier of the module (e.g., "sct").
    Name() string
    // Run executes the module logic and returns when finished or context is canceled.
    Run(ctx context.Context, deps Deps) error
}

// Engine orchestrates execution of one or more modules.
// It does not know about module internals; it only sequences them with shared dependencies.
type Engine struct {
    Deps    Deps
    Modules []Module
}

// Run invokes modules sequentially. Concurrency across modules can be added later if needed.
func (e *Engine) Run(ctx context.Context) error {
    for _, m := range e.Modules {
        if err := m.Run(ctx, e.Deps); err != nil {
            return err
        }
    }
    return nil
}

