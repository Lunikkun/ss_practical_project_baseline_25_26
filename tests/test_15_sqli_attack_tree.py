import uuid
from test_utils import _find_document_id, _login, _upload_document, _url, _wait_for_service

SQLI_PAYLOAD = "' UNION SELECT password FROM users --"

def test_sqli_attack_tree_blocks_suspicious_search_payload_documents():

    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    response = alice.get(_url("/documents"), params={"search": SQLI_PAYLOAD}, timeout=10)

    assert response.status_code == 400
    assert "Invalid search query" in response.text

def test_sqli_attack_tree_blocks_suspicious_search_payload_shared():

    _wait_for_service()

    bob = _login("bob", "De586:Iq6}?!")
    response = bob.get(_url("/shared"), params={"search": "' OR 1=1 --"}, timeout=10)

    assert response.status_code == 400
    assert "Invalid search query" in response.text

def test_sqli_attack_tree_search_functionality_remains_usable_for_legit_terms():

    _wait_for_service()

    alice = _login("alice", "tth1mJj5?£58")
    title_keep = f"scenario9-keep-{uuid.uuid4().hex[:8]}"
    title_hide = f"scenario9-hide-{uuid.uuid4().hex[:8]}"

    _upload_document(alice, title_keep, "keep.txt", b"keep")
    _upload_document(alice, title_hide, "hide.txt", b"hide")

                                   
    _find_document_id(alice, title_keep)
    _find_document_id(alice, title_hide)

    response = alice.get(_url("/documents"), params={"search": title_keep}, timeout=10)

    assert response.status_code == 200
    assert title_keep in response.text
    assert title_hide not in response.text

def test_sqli_attack_tree_no_dynamic_sql_string_concatenation_regression():

    with open("web/app/app.py", "r", encoding="utf-8") as f:
        source = f.read()

    assert "execute(f\"" not in source
    assert "execute(f'" not in source
    assert ".format(" not in source
    assert "UNION SELECT" not in source
