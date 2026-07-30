# ci/

`workflows/ci.yml` is a copy of `.github/workflows/ci.yml` (the authoritative CI
definition: Go build/vet/test -race per module, pytest for analytics, npm ci +
tsc + build for gov-console).

The copy exists as a fallback for the HARDENING H6 push rule: if a token
without the `workflow` scope cannot push `.github/workflows/*`, this directory
carries the workflow so a maintainer with the scope can move it into place:

```sh
mkdir -p .github/workflows
cp ci/workflows/ci.yml .github/workflows/ci.yml
```

Keep both copies in sync when editing CI.
