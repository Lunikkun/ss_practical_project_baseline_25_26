def test_monitoring_regression_denied_access_logging_hooks_present():

    with open("web/app/routes/common.py", "r", encoding="utf-8") as f:
        common_source = f.read()
    with open("web/app/routes/documents.py", "r", encoding="utf-8") as f:
        documents_source = f.read()

    assert "def log_denied_document_access(" in common_source
    assert "Denied document access action=%s doc_id=%s user_id=%s ip=%s status=%s" in common_source

    for action in ("details", "share", "revoke", "download"):
        assert f'log_denied_document_access("{action}"' in documents_source

    assert 'denied_access_callback=log_denied_document_access' in documents_source
    assert 'denied_action="shared_download"' in documents_source
