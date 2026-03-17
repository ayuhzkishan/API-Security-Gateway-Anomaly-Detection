from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import httpx
import uvicorn
import logging

app = FastAPI(title="API Security Gateway")
BACKEND_URL = "http://localhost:8001"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def forward_request(request: Request, path: str, body: bytes = b""):
    url = f"{BACKEND_URL}/{path}"

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient() as client:
        try:
            proxy_req = client.build_request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                params=request.query_params
            )
            proxy_res = await client.send(proxy_req)
            return Response(
                content=proxy_res.content,
                status_code=proxy_res.status_code,
                headers=dict(proxy_res.headers)
            )
        except httpx.RequestError as exc:
            logger.error(f"Error proxying {exc.request.url!r}: {exc}")
            return JSONResponse(content={"error": "Backend service unavailable"}, status_code=502)

from gateway.security.jwt_auth import verify_jwt, create_token
from gateway.security.rate_limiter import check_rate_limit
from gateway.security.waf import apply_waf_rules
from gateway.database import log_request, block_ip, is_ip_blocked
from gateway.ml.model import anomaly_detector

@app.get("/token")
async def generate_test_token():
    # ⚠️  DEV/DEMO only — remove or add credential check before any real deployment.
    # This endpoint issues tokens without authentication, which is intentional
    # for local testing only. Anyone with network access can get a valid JWT.
    token = create_token({"user": "test_user"})
    return {"token": token}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def gateway(request: Request, path: str):
    """
    Main Gateway Route. Refers proxy requests to the backend.
    Pipeline: IP block check → Rate Limit → Body read → WAF → JWT → ML → Proxy
    """
    client_ip = request.client.host if request.client else "unknown"
    anomaly_score = 0.0

    # 0. Check if IP is already permanently blocked
    if is_ip_blocked(client_ip):
        raise HTTPException(status_code=403, detail="IP is permanently blocked due to suspicious activity")

    try:
        # 1. Rate Limiting
        check_rate_limit(request)

        # 2. Read body ONCE here — passed to WAF and ML to avoid double-read
        body = b""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
            except Exception:
                pass

        # 3. WAF Rules — body pre-read and passed in to avoid re-consuming the stream
        await apply_waf_rules(request, body)

        # 4. JWT Auth verification (skip for token endpoint)
        if path != "token":
            verify_jwt(request)

        # 5. ML Anomaly Detection inference
        request_data = {
            "payload_size": len(body),
            "path": path,
            "method": request.method,
            "headers": dict(request.headers)
        }

        is_anomalous, anomaly_score = anomaly_detector.predict(request_data)

        if is_anomalous:
            log_request(client_ip, path, request.method, len(body), anomaly_score, "BLOCKED", "ML Anomaly Detected")
            block_ip(client_ip, f"ML Anomaly Detected (Score: {anomaly_score:.2f})")
            raise HTTPException(status_code=403, detail="Blocked by AI Gateway: Anomalous request profile")

        # Log safe request
        log_request(client_ip, path, request.method, len(body), anomaly_score, "ALLOWED", "")

        return await forward_request(request, path, body)

    except HTTPException as e:
        # Log the exception block dynamically (WAF, Rate Limit, etc.)
        if e.status_code in [401, 403, 429]:
            log_request(client_ip, path, request.method, len(body) if 'body' in locals() else 0, anomaly_score, "BLOCKED", str(e.detail))
            # Auto-block IP on WAF or ML detection
            if "WAF Block" in str(e.detail):
                block_ip(client_ip, str(e.detail))
        raise e

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=8000, reload=True)
