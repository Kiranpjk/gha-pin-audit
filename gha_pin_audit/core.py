"""Rules that audit GitHub Actions workflow files for supply-chain and permission risks."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BRANCH_REFS = {"main", "master", "develop", "dev", "trunk", "HEAD"}
DEFAULT_TRUSTED = ("actions", "github")
# Untrusted event fields that attackers control (title, body, branch name, ...).
INJECTION_RE = re.compile(
    r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|pages|commits)"
    r"[^}]*\.(title|body|message|name|label|ref|email)|head_ref)\s*\}\}"
)
HEAD_CHECKOUT_RE = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref")


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule: str
    severity: str  # "error" | "warning"
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records the source line of every mapping as `__line__`."""


def _construct_mapping(loader, node, deep=False):
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _triggers(doc: dict) -> set[str]:
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(k) for k in on if k != "__line__"}
    return set()


def check_uses(uses: str, trusted: tuple[str, ...]) -> tuple[str, str, str] | None:
    """Return (rule, severity, message) for a `uses:` value, or None if it is fine."""
    uses = uses.strip()
    if uses.startswith("./"):
        return None  # local action, versioned with the repo
    if uses.startswith("docker://"):
        if "@sha256:" in uses:
            return None
        return ("PIN003", "warning", f"Docker action '{uses}' is not pinned to a digest (@sha256:...)")
    if "@" not in uses:
        return ("PIN002", "error", f"'{uses}' has no ref at all; it follows the default branch")
    target, ref = uses.rsplit("@", 1)
    owner = target.split("/", 1)[0].lower()
    if SHA_RE.match(ref):
        return None
    if ref in BRANCH_REFS:
        return ("PIN002", "error", f"'{uses}' tracks branch '{ref}'; any push changes what runs")
    if owner in trusted:
        return None
    return (
        "PIN001",
        "error",
        f"'{uses}' uses mutable ref '{ref}'; pin third-party actions to a full commit SHA",
    )


def audit_workflow(text: str, filename: str = "<workflow>", trusted=DEFAULT_TRUSTED) -> list[Finding]:
    trusted = tuple(t.lower() for t in trusted)
    findings: list[Finding] = []

    def add(line, rule, severity, message):
        findings.append(Finding(filename, line, rule, severity, message))

    try:
        doc = yaml.load(text, Loader=_LineLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        add(mark.line + 1 if mark else 1, "YAML", "error", f"invalid YAML: {exc}")
        return findings
    if not isinstance(doc, dict):
        return findings

    triggers = _triggers(doc)
    top_perms = doc.get("permissions")
    if top_perms == "write-all":
        add(doc["__line__"], "PERM002", "error", "top-level 'permissions: write-all' grants every scope")

    jobs = doc.get("jobs") or {}
    for job_name, job in jobs.items():
        if job_name == "__line__" or not isinstance(job, dict):
            continue
        jline = job.get("__line__", 1)
        perms = job.get("permissions")
        if perms == "write-all":
            add(jline, "PERM002", "error", f"job '{job_name}' sets 'permissions: write-all'")
        if top_perms is None and perms is None:
            add(
                jline,
                "PERM001",
                "warning",
                f"job '{job_name}' has no 'permissions:' block (inherits the repo default token scope)",
            )
        if isinstance(job.get("uses"), str):  # reusable workflow call
            res = check_uses(job["uses"], trusted)
            if res:
                add(jline, *res)
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            sline = step.get("__line__", jline)
            uses = step.get("uses")
            if isinstance(uses, str):
                res = check_uses(uses, trusted)
                if res:
                    add(sline, *res)
                with_ = step.get("with") or {}
                if (
                    "pull_request_target" in triggers
                    and uses.split("@")[0] == "actions/checkout"
                    and HEAD_CHECKOUT_RE.search(str(with_.get("ref", "")))
                ):
                    add(
                        sline,
                        "PRT001",
                        "error",
                        "pull_request_target checks out the PR head: untrusted code runs with secrets",
                    )
            run = step.get("run")
            if isinstance(run, str) and INJECTION_RE.search(run):
                add(
                    sline,
                    "INJ001",
                    "warning",
                    "attacker-controlled expression used directly in 'run:'; pass it via env: instead",
                )
    return findings


def find_workflows(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            wf = p / ".github" / "workflows"
            base = wf if wf.is_dir() else p
            files += sorted(base.glob("*.yml")) + sorted(base.glob("*.yaml"))
        elif p.is_file():
            files.append(p)
    return files
