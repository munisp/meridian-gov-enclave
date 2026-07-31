"""PII redactor: NIN (11 digits) + phone/MSISDN masking."""
from hermes.agent.guardrails import redact_text, redact_value


def test_nin_masked():
    out = redact_text("NIN 12345678901 captured")
    assert "12345678901" not in out
    assert "12*******01" in out


def test_phone_masked():
    for phone in ("08031234567", "+2348031234567", "2348031234567"):
        out = redact_text(f"call {phone} now")
        assert phone not in out


def test_nested_redaction():
    doc = {"a": [{"nin": "12345678901"}], "b": "ok"}
    out = redact_value(doc)
    assert "12345678901" not in str(out)
    assert out["b"] == "ok"


def test_tin_like_8_digits_untouched():
    # TINs are references, not masked PII per spec (refs allowed)
    assert "12345678" in redact_text("TIN 12345678")
