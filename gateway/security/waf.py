import re
from fastapi import Request, HTTPException

# Simple regex-based WAF for common attack patterns
SQLI_PATTERN = re.compile(r"(?i)(union\s+select|select\s+.+from|insert\s+into|update\s+.+set|delete\s+from|drop\s+table|--|;\s*--|'\s*or\s*'?\d+\s*'?\s*=\s*'?\d+)")
XSS_PATTERN = re.compile(r"(?i)(<\s*script[\s>]|<\s*img[^>]+onerror\s*=|javascript\s*:|on\w+\s*=\s*[\"'])")

# LLM Prompt Injection detection (supply-chain / LLM era attack surface)
PROMPT_INJECTION_PATTERN = re.compile(
    r"(?i)(ignore\s+(previous|all)\s+instructions|you\s+are\s+now\s+(a|an)|"
    r"act\s+as\s+(a|an|if)|jailbreak|dan\s+mode|forget\s+your\s+training|"
    r"new\s+persona|system\s*:\s*(you|ignore)|<\|?system\|?>)"
)


async def apply_waf_rules(request: Request, body: bytes = b""):
    """
    Run WAF checks against query params and body.

    Parameters
    ----------
    request : Request
        The incoming FastAPI request.
    body : bytes, optional
        Pre-read request body. If empty and method allows a body,
        the body will be read here. Passing it avoids a double-read.
    """
    # --- Check query params ---
    for key, value in request.query_params.items():
        if SQLI_PATTERN.search(value):
            raise HTTPException(status_code=403, detail="WAF Block: SQL Injection detected in query")
        if XSS_PATTERN.search(value):
            raise HTTPException(status_code=403, detail="WAF Block: XSS detected in query")
        if PROMPT_INJECTION_PATTERN.search(value):
            raise HTTPException(status_code=403, detail="WAF Block: Prompt Injection detected in query")

    # --- Check path ---
    if SQLI_PATTERN.search(request.url.path):
        raise HTTPException(status_code=403, detail="WAF Block: SQL Injection detected in path")

    # --- Check body ---
    method = request.method
    if method in ["POST", "PUT", "PATCH"]:
        if not body:
            try:
                body = await request.body()
            except UnicodeDecodeError:
                return  # Non-text body, skip text-based checks
        try:
            body_str = body.decode("utf-8", errors="ignore")
        except Exception:
            return

        if SQLI_PATTERN.search(body_str):
            raise HTTPException(status_code=403, detail="WAF Block: SQL Injection detected in body")
        if XSS_PATTERN.search(body_str):
            raise HTTPException(status_code=403, detail="WAF Block: XSS detected in body")
        if PROMPT_INJECTION_PATTERN.search(body_str):
            raise HTTPException(status_code=403, detail="WAF Block: Prompt Injection detected in body")
