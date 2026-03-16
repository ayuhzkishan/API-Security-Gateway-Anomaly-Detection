import re
from fastapi import Request, HTTPException

# Simple regex-based WAF for basic attacks
SQLI_PATTERN = re.compile(r"(?i)(union|select|insert|update|delete|drop|--|;|\bOR\b.+=\s*.+)")
XSS_PATTERN = re.compile(r"(?i)(<script>|<img.*onerror=.*>|javascript:)")

async def apply_waf_rules(request: Request):
    # Check query params
    for key, value in request.query_params.items():
        if SQLI_PATTERN.search(value):
            raise HTTPException(status_code=403, detail="WAF Block: SQL Injection detected in query")
        if XSS_PATTERN.search(value):
            raise HTTPException(status_code=403, detail="WAF Block: XSS detected in query")
            
    # Check body if method allows body
    method = request.method
    if method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.body()
            body_str = body.decode('utf-8', errors='ignore')
            if SQLI_PATTERN.search(body_str):
                raise HTTPException(status_code=403, detail="WAF Block: SQL Injection detected in body")
            if XSS_PATTERN.search(body_str):
                raise HTTPException(status_code=403, detail="WAF Block: XSS detected in body")
        except Exception:
            pass
