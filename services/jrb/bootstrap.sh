#!/usr/bin/env sh
# bootstrap.sh — QA-18: regenerate the CI-maintained go.sum for this module.
#
# This module's go.sum is NOT committed (workspace policy: no lockfile-class
# artifacts). A clean checkout therefore cannot `go build` until go.sum is
# regenerated locally. Run this once after cloning:
#
#     services/jrb/bootstrap.sh        # from the repo root, or
#     ./bootstrap.sh                   # from services/jrb
#
# It is idempotent and only touches services/jrb/go.sum.
set -eu
cd "$(dirname "$0")"
go mod tidy
echo "jrb bootstrap complete: go.sum regenerated; go build ./... now works."
