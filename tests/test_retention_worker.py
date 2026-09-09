import retention_worker


def test_retention_dry_run_never_deletes(monkeypatch):
    monkeypatch.setattr(retention_worker, "retention_candidates_all", lambda days: [{"sha256": "a" * 64}])
    monkeypatch.setattr(retention_worker, "purge_capture", lambda *args: (_ for _ in ()).throw(AssertionError("must not purge")))
    assert retention_worker.run_cycle(True) == {"candidates": 1, "purged": 0, "failed": 0, "dry_run": True}


def test_retention_purges_each_workspace_and_audits(monkeypatch):
    purges, audits = [], []
    monkeypatch.setattr(retention_worker, "retention_candidates_all", lambda days: [{"sha256": "b" * 64}])
    monkeypatch.setattr(retention_worker, "capture_workspaces", lambda sha: ["workspace-a", "workspace-b"])
    monkeypatch.setattr(retention_worker, "purge_capture", lambda sha, workspace: purges.append((sha, workspace)) or True)
    monkeypatch.setattr(retention_worker, "audit", lambda *args: audits.append(args))
    result = retention_worker.run_cycle(False)
    assert result["purged"] == 1 and result["failed"] == 0
    assert len(purges) == 2 and len(audits) == 2
