"""The local HTTP service and the dashboard it serves.

The problem statement names an interactive platform as a deliverable, so these
guard the contract the dashboard depends on: the same engine the CLI drives,
reachable over HTTP, with no second source of truth.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qdarpan import cli
from qdarpan.api import WEB_DIR, create_app

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def scanned(tmp_path, sample_repo):
    """A runs root with one completed offline scan of the fixture corpus."""
    runs = tmp_path / "runs"
    cli.main(
        ["scan", str(sample_repo), "--out", str(runs), "--surface", "source",
         "--offline", "--reproducible", "--quiet"]
    )
    return runs


@pytest.fixture
def client(scanned):
    """A client whose portal thread is actually shut down afterwards.

    TestClient starts a background event-loop thread. Returning one without
    closing it leaks a thread per test, and once enough of them accumulate the
    interpreter starts failing in places that have nothing to do with the leak
    -- a segfault in one run, an IndexError deep inside sortedcontainers in the
    next. Both were symptoms of this.
    """
    with TestClient(create_app(scanned)) as test_client:
        yield test_client


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["version"]


def test_dashboard_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Q-DARPAN" in response.text


def test_dashboard_is_self_contained():
    """No CDN, no web fonts, no external anything.

    This is the air-gap promise in file form: an enclave that resolves nothing
    must still render the whole UI.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    for offender in ("http://", "https://", "//cdn", "src=\"//"):
        assert offender not in html, "dashboard reaches outside for %r" % offender


def test_dashboard_reads_only_fields_the_api_sends(client):
    """The page renders size deltas; those field names must exist in the JSON.

    Reading d.before instead of d.before_bytes rendered "undefined -> undefined B"
    in the wire-cost column while every API test still passed, because nothing
    tied the two field vocabularies together. This does.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    body = client.get("/api/runs/reproducible").json()
    deltas = [
        d
        for entry in body["queue"]
        if entry.get("recommendation")
        for d in entry["recommendation"]["size_deltas"]
    ]
    assert deltas, "fixture must produce at least one size delta to check against"
    served = set(deltas[0])

    for referenced in ("before_bytes", "after_bytes", "delta_bytes", "ratio", "field"):
        assert referenced in served, referenced
        assert referenced in html, "dashboard never reads %s" % referenced

    # The pre-serialisation names must not appear as delta property reads.
    for stale in ("d.before ", "d.after ", "d.delta "):
        assert stale not in html, "dashboard reads %r, which the API does not send" % stale


def test_runs_are_listed(client):
    runs = client.get("/api/runs").json()["runs"]
    assert len(runs) == 1
    assert runs[0]["id"] == "reproducible"
    assert runs[0]["target_count"] == 1


def test_run_detail_matches_the_cli(client, scanned):
    """The API and the CLI must not disagree -- one engine, one answer."""
    body = client.get("/api/runs/reproducible").json()
    assert body["summary"]["by_tier"]["critical"] > 0
    assert body["queue"]

    from qdarpan.journal import RunJournal
    from qdarpan.pipeline import analyse

    analysis = analyse(RunJournal.open(scanned / "reproducible"))
    assert len(body["queue"]) == len(analysis.queue)
    assert body["queue"][0]["name"] == analysis.queue[0].assessment.name


def test_queue_entries_carry_what_the_ui_renders(client):
    entry = client.get("/api/runs/reproducible").json()["queue"][0]
    for field in ("name", "tier", "target_id", "confidence", "blast_radius",
                  "rationale", "surfaces", "locations", "deadlines"):
        assert field in entry, field


def test_libraries_are_reported_apart_from_the_queue(client):
    """Libraries are inventory. They belong on screen, not in the queue."""
    body = client.get("/api/runs/reproducible").json()
    assert body["summary"]["libraries"] > 0
    queue_names = {e["name"] for e in body["queue"]}
    assert not any(lib["name"] in queue_names for lib in body["libraries"])


def test_cbom_endpoint_returns_cyclonedx_1_7(client):
    body = client.get("/api/runs/reproducible/cbom").json()
    assert body["bomFormat"] == "CycloneDX"
    assert body["specVersion"] == "1.7"


def test_report_endpoint_returns_markdown(client):
    text = client.get("/api/runs/reproducible/report").text
    assert "Migration queue" in text


def test_policy_endpoint_exposes_the_registry(client):
    body = client.get("/api/policy").json()
    assert "RSA" in body["families"]
    assert body["policy"]["quantum_timeline"]["scenarios"]["median"]


def test_unknown_run_is_404(client):
    assert client.get("/api/runs/nope").status_code == 404


def test_path_traversal_is_refused(client):
    """The run id comes from a URL and this process can read the whole disk.

    Only encoded separators are tested: a literal "/api/runs/../.." is
    collapsed to "/api/runs" by the HTTP layer before routing, so it reaches
    the list endpoint and correctly returns 200. The encoded forms are the ones
    that actually arrive at the handler as a run id.
    """
    for attempt in ("..%2F..", "..%2F..%2Fetc", "%2e%2e%2f%2e%2e"):
        assert client.get("/api/runs/" + attempt).status_code in (400, 404)


def test_scan_endpoint_runs_the_same_pipeline(client, sample_repo, scanned):
    response = client.post(
        "/api/scan",
        json={"targets": [str(sample_repo)], "surfaces": ["source"],
              "offline": True, "run_id": "web"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["run_id"] == "web"
    assert body["scan"]["findings"] > 0

    # The scan must leave the same artefacts on disk the CLI would.
    for name in ("findings.jsonl", "cbom.json", "report.md"):
        assert (scanned / "web" / name).exists(), name


def test_scan_without_targets_is_rejected(client):
    assert client.post("/api/scan", json={"targets": []}).status_code == 400


def test_scan_rejects_a_run_id_that_escapes_the_runs_root(client, sample_repo):
    response = client.post(
        "/api/scan",
        json={"targets": [str(sample_repo)], "run_id": "../escape", "offline": True},
    )
    assert response.status_code == 400
