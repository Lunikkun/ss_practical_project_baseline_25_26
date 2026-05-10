def test_monitoring_regression_denied_access_logging_hooks_present():
    """
    Regressione scenario 6: assicura che i punti di audit logging per accessi
    negati restino presenti nei path critici documento/share/download.
    """
    with open("web/app/app.py", "r", encoding="utf-8") as f:
        source = f.read()

    assert "def log_denied_document_access(" in source
    assert "Denied document access action=%s doc_id=%s user_id=%s ip=%s status=%s" in source

    for action in ("details", "share", "revoke", "download", "shared_download"):
        assert f'log_denied_document_access("{action}"' in source
