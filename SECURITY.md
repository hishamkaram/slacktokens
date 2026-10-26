# Security policy

## Supported versions

Security fixes are provided for the latest stable release. Upgrade older
installations before reporting an issue. Source builds require the Go version
declared in `go.mod`; installed binaries must be rebuilt or replaced to receive
standard-library security fixes.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/hishamkaram/slacktokens/security/advisories/new)
for vulnerabilities in this project. Include the affected version and platform,
the trust boundary crossed, expected and observed behavior, and a minimal
reproduction using dummy data.

Do not include real Slack tokens, cookies, workspace data, or OS keychain
contents. Do not disclose an unpatched vulnerability in a public issue.

## Automated checks

Dependabot monitors application and security-tool Go modules and GitHub Actions.
Routine updates run weekly; security updates follow GitHub advisories. All
update PRs are merged manually after the required checks pass.

Dependency review blocks newly introduced high/critical advisories. CodeQL
checks Go and GitHub Actions; merge protection blocks high/critical security
alerts and error-level findings. Lower-severity alerts require triage, and are
not automatically dismissed. `govulncheck` checks application reachability in CI,
daily across all release targets, and before publishing. Module-level advisories
can concern packages that the application does not call.

OpenSSF Scorecard reports repository practices on changes to `main` and weekly.
Its score is informational and is not a promise that the application is free of
vulnerabilities.
