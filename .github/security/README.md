# Repository security administration

GitHub owns the live repository settings. The maintainer applies the reviewed
API payloads in this directory and verifies the resulting state. These files do
not automatically change GitHub settings.

After review, before opening the baseline PR, apply the first operation in
`repository-settings.json` (`PUT .../vulnerability-alerts`). This also enables
the dependency graph, which the dependency-review PR check needs. Read back the
alerts setting and confirm the dependency-comparison API is available. Leave
security-update PRs disabled until the configuration is merged.

After the baseline PR and the first `main` scans pass:

1. Apply the remaining operations in `repository-settings.json` using `gh api --method`,
   passing its `body` as JSON when present. Preserve the already enabled secret
   scanning and push protection. No credentials belong in these files.
2. Confirm that the thirteen contexts in `main-ruleset.json` exist and originate
   from the GitHub Actions integration (ID 15368). Create the ruleset with
   `POST /repos/hishamkaram/slacktokens/rulesets`, or update the existing
   `main-security-baseline` ruleset by ID with `PUT`; do not create duplicates.
3. Read back the settings, ruleset, and effective rules for `main`. Verify PRs,
   current branches, required checks, CodeQL thresholds, and zero bypass actors.
   Scorecard is informational and must not become a required PR check.
4. Rerun the `main` Scorecard workflow after activation, since its initial run
   may have inspected the old settings. Confirm SARIF upload and publication.

CodeQL uses advanced workflow setup; do not also enable default setup. PR jobs
must work with read-only fork/Dependabot credentials and no publishing secrets.
Do not use `pull_request_target` to give untrusted code write permissions.

The application `go.mod` owns the CI/release toolchain version. The separate
tools module owns the `govulncheck` and gosec package versions; install them from
that module, then run them against the application from the repository root.
Dependabot monitors both modules. The pinned golangci-lint and GoReleaser binary
versions are workflow inputs and need manual updates; Dependabot updates their
action references, not those inputs.

Security updates are event-driven. Weekly grouping only applies to routine
patch/minor version updates; major and security PRs remain separate. All merges
are manual. Review initial alerts individually; do not dismiss them merely
because a module-level or stripped-binary scan cannot establish reachability.

Routine Go update PRs are capped at three for the application and two for the
tools module. Tools allow indirect updates because Go tool directives produce
indirect requirements; application indirects follow their parent dependencies.
CodeQL uses separate Linux, macOS, and Windows Go build configurations so that
platform-specific credential code is included, plus a GitHub Actions analysis.
