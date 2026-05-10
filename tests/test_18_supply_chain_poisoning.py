from pathlib import Path

from test_utils import _wait_for_service


def test_supply_chain_poisoning_controls_are_locked_down():
    """
    Scenario 12: la build pipeline deve installare solo da lock file hash-locked.
    """
    _wait_for_service()

    dockerfile = Path("web/Dockerfile").read_text(encoding="utf-8")
    requirements = Path("web/requirements.txt").read_text(encoding="utf-8")
    lockfile = Path("web/requirements.lock").read_text(encoding="utf-8")

    assert "COPY requirements.lock ." in dockerfile
    assert "--require-hashes -r requirements.lock" in dockerfile
    assert "requirements.txt" not in dockerfile
    assert "PyYAML" not in requirements
    assert "PyYAML" not in lockfile
    assert "--hash=sha256:" in lockfile


def test_supply_chain_poisoning_lockfile_covers_all_packages():
    """
    Regressione statica: ogni pacchetto nel lock deve essere hashato.
    """
    lock_lines = [line for line in Path("web/requirements.lock").read_text(encoding="utf-8").splitlines() if line]

    blocks = []
    current_hashes = None

    for line in lock_lines:
        if not line.startswith("    "):
            if current_hashes is not None:
                blocks.append(current_hashes)
            current_hashes = 0
            continue

        if "--hash=sha256:" in line and current_hashes is not None:
            current_hashes += 1

    if current_hashes is not None:
        blocks.append(current_hashes)

    assert blocks, "requirements.lock must contain pinned packages"
    assert all(hash_count >= 1 for hash_count in blocks), "Every locked package must have at least one hash"