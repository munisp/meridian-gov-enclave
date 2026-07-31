# CI note: go.sum

`go.sum` in this module is **CI-regenerated** (`go mod tidy` in the pipeline).
Do not commit hand-edited `go.sum` changes; only `go.mod` is maintained in
commits. The 2026-07 hardening sweep (f1e79b6) dropped the indirect-require
block from `go.mod` while the dependencies were still in use; the block was
restored via `go mod tidy` (go 1.23, `rogpeppe/go-internal` pinned to v1.12.0
because v1.15.0 requires go >= 1.25).
