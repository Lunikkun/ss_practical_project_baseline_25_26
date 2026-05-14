import os
import pathlib
import re
from werkzeug.utils import secure_filename


MAX_SEARCH_QUERY_LENGTH = int(os.getenv("MAX_SEARCH_QUERY_LENGTH", "100"))

DISALLOWED_UPLOAD_EXTENSIONS = {
    ".bat",
    ".bin",
    ".cjs",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".htm",
    ".html",
    ".js",
    ".jsp",
    ".jspx",
    ".mjs",
    ".msi",
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".phtml",
    ".pl",
    ".py",
    ".pyc",
    ".rb",
    ".sh",
    ".svg",
    ".war",   
    ".bash",     
    ".csh",     
}

_SQLI_SIGNATURE_RE = re.compile(
    r"(?:union\s+select|select\s+.+\s+from|or\s+1\s*=\s*1|--|/\*|;|information_schema)",
    re.IGNORECASE,
)

_XSS_TITLE_SIGNATURE_RE = re.compile(
    r"(?:<\s*/?\s*script\b|javascript:|on\w+\s*=|<|>)",
    re.IGNORECASE,
)


def normalize_search_query(raw_query: str) -> str:
    return (raw_query or "").strip()[:MAX_SEARCH_QUERY_LENGTH]


def is_suspicious_search_query(query: str) -> bool:
    return bool(_SQLI_SIGNATURE_RE.search(query))


def is_safe_document_title(title: str) -> bool:
    normalized = (title or "").strip()
    if not normalized:
        return False
    return _XSS_TITLE_SIGNATURE_RE.search(normalized) is None


def is_safe_upload(filename):
    sanitized_name = secure_filename(filename or "")
    if not sanitized_name:
        return False, "Invalid file name."

    extension = pathlib.Path(sanitized_name).suffix.lower()
    if extension in DISALLOWED_UPLOAD_EXTENSIONS:
        return False, "File type not allowed."

    return True, sanitized_name
