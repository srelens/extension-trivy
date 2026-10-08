# Historical local scanner feasibility proof

This optional nested module preserves the earlier in-process scanner experiment.
It is not part of the normal Trivy controller build or the in-cluster fallback.

Prepare the pinned host, source and fixtures from the repository root using
`scripts/prepare_host.py`, `scripts/prepare_trivy.py` and
`scripts/prepare_fixtures.py`. Then run `go test -race ./...` in this directory.
The exact source/fixture pins and measured platform limits remain documented in
`docs/feasibility.md` at the repository root. No scanner/database is packaged
with the production controller.
