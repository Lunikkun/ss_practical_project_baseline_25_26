import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "web"

DISALLOWED_PATTERNS = {
    r"\bos\.popen\(": "os.popen executes a shell command",
    r"\bos\.system\(": "os.system executes a shell command",
    r"\bsubprocess\.(run|Popen|call|check_call|check_output)\(.*shell\s*=\s*True": "subprocess with shell=True allows shell injection",
    r"\beval\(": "eval executes dynamic Python code",
    r"\bexec\(": "exec executes dynamic Python code",
}

def test_no_rce():
    findings = []

    for file_path in sorted(SOURCE_ROOT.rglob("*.py")):
        relative_path = file_path.relative_to(REPO_ROOT)
        for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pattern, reason in DISALLOWED_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append(f"{relative_path}:{line_number}: {reason}: {stripped}")

    assert not findings, "Potential RCE sinks found:\n" + "\n".join(findings)