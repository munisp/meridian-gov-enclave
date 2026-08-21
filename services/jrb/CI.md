# CI note: go.sum

`go.sum` in this module is **CI-regenerated** (`go mod tidy` in the pipeline)
and is intentionally NOT committed (workspace policy: no lockfile-class
artifacts). Only `go.mod` is maintained in commits. The 2026-07 hardening
sweep (f1e79b6) dropped the indirect-require block from `go.mod` while the
dependencies were still in use; the block was restored via `go mod tidy`
(go 1.23, `rogpeppe/go-internal` pinned to v1.12.0 because v1.15.0 requires
go >= 1.25).

## QA-18: clean-checkout bootstrap is REQUIRED

`go build ./...` FAILS on a clean checkout (missing go.sum entries for the
pgx transitive deps `golang.org/x/text/secure/precis` and
`golang.org/x/sync/semaphore`). This is by design under the no-go.sum
policy; the committed file set cannot be made self-sufficient without
committing a lockfile-class artifact.

Bootstrap once after cloning (idempotent; only regenerates `go.sum`):

```sh
services/jrb/bootstrap.sh    # from the repo root
# or, from services/jrb:
make bootstrap               # == go mod tidy
```

After bootstrapping, `go build ./... && go vet ./... && go test ./...` all
pass (verified on go 1.23 with a clean module cache). CI performs the same
`go mod tidy` step (ci/workflows/ci.yml), which is why the pipeline is green
without a committed go.sum.
