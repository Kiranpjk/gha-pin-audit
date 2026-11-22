# gha-pin-audit

[![CI](https://github.com/Kiranpjk/gha-pin-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiranpjk/gha-pin-audit/actions/workflows/ci.yml)

A small, dependency-light linter for GitHub Actions workflows. It catches the supply-chain and
token-permission mistakes behind real CI compromises: third-party actions pinned to a movable tag,
jobs that run with the default (often write) token, `pull_request_target` workflows that check out
untrusted PR code, and `${{ github.event.* }}` values pasted straight into shell scripts.

## The problem

In March 2025 the popular `tj-actions/changed-files` action was compromised: the attacker moved
its version tags to a malicious commit, and every workflow using `@v45`-style refs leaked CI
secrets into build logs ([CISA alert, CVE-2025-30066](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066)).

Community discussion:

- Hacker News thread on the compromise: <https://hn.svelte.dev/item/43367987> (mirror of
  news.ycombinator.com item 43367987). Many commenters say to pin third-party actions to commit
  SHAs and to keep secrets and token scopes tight, and point out that this is easy to forget across
  dozens of workflow files.

> Research note: the brief asked for Reddit threads (r/devops). Reddit was not reachable from the
> environment this was built in (blocked by the network proxy, and not returned by the search
> tool), so the sources above are the closest verified public discussions. Please swap in a Reddit
> thread if you find one.

Doing this by hand across many repos is tedious, so this tool does the checking and plugs into CI.

## Rules

| Rule    | Severity | What it flags |
|---------|----------|---------------|
| PIN001  | error    | Third-party action/reusable workflow on a mutable tag (`foo/bar@v1`) instead of a 40-char commit SHA |
| PIN002  | error    | Any action on a branch (`@main`, `@master`, ...) or with no ref at all, even trusted owners |
| PIN003  | warning  | `docker://` action without an `@sha256:` digest |
| PERM001 | warning  | Job with no `permissions:` block and no top-level one (inherits the repo default token) |
| PERM002 | error    | `permissions: write-all` |
| PRT001  | error    | `pull_request_target` workflow that checks out `github.event.pull_request.head.*` ("pwn request") |
| INJ001  | warning  | Attacker-controlled expression (issue/PR title, body, branch name, commit message) used in `run:` |

Actions owned by `actions` and `github` may use tags (they are GitHub's own). Add more trusted
owners with `--trust OWNER`. Local actions (`./...`) are ignored.

## Demo

Output from a real local run against a deliberately bad workflow (`/tmp/demo-repo/.github/workflows/pr.yml`):

```console
$ gha-pin-audit
.github/workflows/pr.yml:7: warning [PERM001] job 'changed' has no 'permissions:' block (inherits the repo default token scope)
.github/workflows/pr.yml:9: error [PRT001] pull_request_target checks out the PR head: untrusted code runs with secrets
.github/workflows/pr.yml:12: error [PIN001] 'tj-actions/changed-files@v45' uses mutable ref 'v45'; pin third-party actions to a full commit SHA
.github/workflows/pr.yml:13: warning [INJ001] attacker-controlled expression used directly in 'run:'; pass it via env: instead
.github/workflows/pr.yml:16: error [PERM002] job 'deploy' sets 'permissions: write-all'
.github/workflows/pr.yml:19: error [PIN002] 'some-org/deploy-action@main' tracks branch 'main'; any push changes what runs
.github/workflows/pr.yml:20: warning [PIN003] Docker action 'docker://ghcr.io/some-org/tool:latest' is not pinned to a digest (@sha256:...)

1 workflow(s) scanned: 4 error(s), 3 warning(s)
$ echo $?
1
```

The repo audits its own workflows in CI (`gha-pin-audit . --trust docker --strict`).

## Install

```bash
pip install git+https://github.com/Kiranpjk/gha-pin-audit.git
# or, from a clone
pip install -e '.[dev]'
```

Requires Python 3.10+ and PyYAML.

## Usage

```bash
gha-pin-audit                         # scan ./.github/workflows
gha-pin-audit ~/src/repo1 ~/src/repo2 # scan several repos
gha-pin-audit wf.yml --format json    # machine-readable output
gha-pin-audit --format github         # ::error annotations shown inline on PRs
gha-pin-audit --trust docker --trust aws-actions
gha-pin-audit --strict                # fail on warnings too
gha-pin-audit --ignore PERM001        # skip a rule
```

Exit codes: `0` clean, `1` findings (errors, or warnings with `--strict`), `2` no workflow files found.

### As a step in your own workflow

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.13"
- run: pip install git+https://github.com/Kiranpjk/gha-pin-audit.git
- run: gha-pin-audit --format github
```

## Run with Docker

```bash
docker build -t gha-pin-audit .
docker run --rm -v "$PWD:/repo:ro" gha-pin-audit
# or the published image
docker run --rm -v "$PWD:/repo:ro" ghcr.io/kiranpjk/gha-pin-audit:main
```

## CI/CD

- `.github/workflows/ci.yml`: on every push and PR: `ruff check`, `ruff format --check`, the
  dogfood audit, `pytest` on Python 3.10 to 3.13, then a Docker build plus `--version` smoke test.
- `.github/workflows/release.yml`: on pushes to `main` and `v*` tags, builds a multi-arch
  (amd64/arm64) image and pushes it to `ghcr.io/kiranpjk/gha-pin-audit` using the built-in
  `GITHUB_TOKEN` (`packages: write`).
- `.github/dependabot.yml`: weekly updates for pip, GitHub Actions and the Docker base image.

## Development

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
pytest -v
```

## License

MIT, see [LICENSE](LICENSE).
