import json

import pytest

from gha_pin_audit.cli import main
from gha_pin_audit.core import audit_workflow, check_uses

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def rules(text, **kw):
    return [f.rule for f in audit_workflow(text, **kw)]


@pytest.mark.parametrize(
    "uses,expected",
    [
        ("actions/checkout@v4", None),
        (f"tj-actions/changed-files@{SHA}", None),
        ("tj-actions/changed-files@v45", "PIN001"),
        ("actions/checkout@main", "PIN002"),
        ("some/action", "PIN002"),
        ("./.github/actions/local", None),
        ("docker://alpine:3.20", "PIN003"),
        ("docker://alpine@sha256:" + "a" * 64, None),
        ("org/repo/.github/workflows/build.yml@v1", "PIN001"),
    ],
)
def test_check_uses(uses, expected):
    res = check_uses(uses, ("actions", "github"))
    assert (res[0] if res else None) == expected


def test_trusted_owner_can_use_tags():
    assert check_uses("docker/build-push-action@v6", ("actions", "docker")) is None
    assert check_uses("Docker/build-push-action@v6", ("docker",)) is None


def test_clean_workflow_has_no_findings():
    wf = f"""
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@{SHA}
      - run: echo ok
"""
    assert rules(wf) == []


def test_missing_permissions_reported_per_job_with_line():
    wf = "on: push\njobs:\n  a:\n    runs-on: x\n    steps: []\n  b:\n    permissions: {}\n    runs-on: x\n"
    findings = audit_workflow(wf, "wf.yml")
    assert [(f.rule, f.line) for f in findings] == [("PERM001", 4)]


def test_write_all_is_error():
    wf = "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n"
    assert rules(wf) == ["PERM002"]


def test_pull_request_target_head_checkout():
    wf = """
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert rules(wf) == ["PRT001"]


def test_head_checkout_is_fine_on_pull_request():
    wf = """
on: [pull_request]
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    assert rules(wf) == []


def test_script_injection():
    wf = """
on: issues
permissions: {}
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
      - run: echo "${{ github.event.issue.number }}"
"""
    assert rules(wf) == ["INJ001"]


def test_reusable_workflow_job_checked():
    wf = "on: push\npermissions: {}\njobs:\n  call:\n    uses: org/shared/.github/workflows/ci.yml@main\n"
    assert rules(wf) == ["PIN002"]


def test_invalid_yaml_reported():
    assert rules("jobs: [unclosed") == ["YAML"]


def test_cli_exit_codes_and_json(tmp_path, capsys):
    wfdir = tmp_path / ".github" / "workflows"
    wfdir.mkdir(parents=True)
    (wfdir / "ci.yml").write_text("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: foo/bar@v1\n")
    assert main([str(tmp_path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert {d["rule"] for d in data} == {"PIN001", "PERM001"}

    assert main([str(tmp_path), "--trust", "foo"]) == 0  # only a warning left
    assert main([str(tmp_path), "--trust", "foo", "--strict"]) == 1
    assert main([str(tmp_path), "--trust", "foo", "--strict", "--ignore", "PERM001"]) == 0


def test_cli_github_annotations(tmp_path, capsys):
    f = tmp_path / "wf.yml"
    f.write_text("on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: foo/bar@v1\n")
    main([str(f), "--format", "github"])
    assert capsys.readouterr().out.startswith(f"::error file={f},line=6,title=PIN001::")


def test_cli_no_files(tmp_path):
    assert main([str(tmp_path)]) == 2
