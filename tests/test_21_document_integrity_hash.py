import hashlib
from web.app.services.storage_service import compute_file_hash

def test_compute_file_hash_returns_sha256_hex_digest(tmp_path):
    payload = b"document-integrity-payload"
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    observed = compute_file_hash(file_path)
    assert observed == expected
    assert len(observed) == 64
