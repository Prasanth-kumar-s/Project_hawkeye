# utils/email_parser.py
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any

def parse_raw_email(raw: bytes) -> Dict[str, Any]:
    """
    Minimal RFC822 parser that returns headers and plain-text body where possible.
    raw: bytes of the email message.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        # try text parse as fallback
        try:
            msg = Parser(policy=policy.default).parsestr(raw.decode("utf-8", errors="ignore"))
        except Exception:
            return {"error": "parse_failed"}

    headers = dict(msg.items())
    subject = msg.get("subject", "")
    from_ = msg.get("from", "")
    to = msg.get("to", "")
    # get plain text body if present
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content().strip())
                except Exception:
                    pass
        body = "\n\n".join(parts) if parts else ""
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    return {
        "subject": subject,
        "from": from_,
        "to": to,
        "headers": headers,
        "body": body
    }
