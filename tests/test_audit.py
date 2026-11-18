import json

from preflight.safety.audit import AuditLog, redact_headers, redact_json, redact_text, redact_url


def test_chain_verifies_and_resumes(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append("a", x=1)
    log.append("b", y=2)
    AuditLog(p).append("c")  # a new instance continues the chain
    v = AuditLog.verify(p)
    assert v.ok and v.entries == 3


def test_tamper_edit_delete_reorder_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.append("e", i=i)
    lines = p.read_text().splitlines()

    p.write_text("\n".join([lines[0], lines[1].replace('"i":1', '"i":9'), *lines[2:]]) + "\n")
    assert not AuditLog.verify(p).ok
    p.write_text("\n".join([lines[0], *lines[2:]]) + "\n")  # deletion
    assert not AuditLog.verify(p).ok
    p.write_text("\n".join([lines[1], lines[0], *lines[2:]]) + "\n")  # reorder
    assert not AuditLog.verify(p).ok


def test_redaction():
    hdr = redact_headers({"Authorization": "Bearer abcdef123456", "Accept": "x"})
    assert hdr["Authorization"] == "[REDACTED]" and hdr["Accept"] == "x"
    out = redact_json(
        {
            "password": "p",
            "nested": {"api_key": "k", "passport_no": "N123"},
            "note": "Bearer abcdef123456",
        }
    )
    assert out["password"] == "[REDACTED]" and out["nested"]["api_key"] == "[REDACTED]"
    assert out["nested"]["passport_no"] == "N123"  # not a secret
    assert "abcdef123456" not in out["note"]
    assert "hunter2" not in redact_text("user=a&password=hunter2")
    assert "s3cr3t" not in redact_url("http://127.0.0.1:8000/x?token=s3cr3t&q=1")
    assert json.loads(redact_text('{"token":"t","q":1}'))["token"] == "[REDACTED]"
