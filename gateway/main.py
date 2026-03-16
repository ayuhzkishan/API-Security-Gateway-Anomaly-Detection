from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import httpx
import uvicorn
import logging

app = FastAPI(title="API Security Gateway")
BACKEND_URL = "http://localhost:8001"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def forward_request(request: Request, path: str):
    url = f"{BACKEND_URL}/{path}"
    
    headers = dict(request.headers)
    headers.pop("host", None)
    
    body = await request.body()
    
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

from gateway.security.jwt_auth import verify_jwt, SECRET_KEY, ALGORITHM
import jwt
from gateway.security.rate_limiter import check_rate_limit
from gateway.security.waf import apply_waf_rules
from gateway.database import log_request, block_ip, is_ip_blocked
from gateway.ml.model import anomaly_detector

@app.get("/token")
async def generate_test_token():
    # Simple endpoint to get a token for testing
    token = jwt.encode({"user": "test_user"}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def gateway(request: Request, path: str):
    """
    Main Gateway Route. Refers proxy requests to the backend.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # 0. Check if IP is already permanently blocked
    if is_ip_blocked(client_ip):
        raise HTTPException(status_code=403, detail="IP is permanently blocked due to suspicious activity")

    try:
        # 1. Rate Limiting
        check_rate_limit(request)
        
        # 2. WAF Rules
        await apply_waf_rules(request)
        
        # 3. JWT Auth verification (skip for token endpoint)
        if path != "token":
            verify_jwt(request)
            
        # 4. ML Anomaly Detection inference
        body = b""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
            except Exception:
                pass
                
        request_data = {
            "payload_size": len(body),
            "path": path,
            "method": request.method,
            "headers": dict(request.headers)
        }
        
        is_anomalous, score = anomaly_detector.predict(request_data)
        
        if is_anomalous:
            log_request(client_ip, path, request.method, len(body), score, "BLOCKED", "ML Anomaly Detected")
            block_ip(client_ip, f"ML Anomaly Detected (Score: {score:.2f})")
            raise HTTPException(status_code=403, detail="Blocked by AI Gateway: Anomalous request profile")

        # Log safe request
        log_request(client_ip, path, request.method, len(body), score, "ALLOWED", "")
            
        return await forward_request(request, path)
        
    except HTTPException as e:
        # Log the exception block dynamically (WAF, Rate Limit, etc.)
        if e.status_code in [401, 403, 429]:
            log_request(client_ip, path, request.method, 0, 0.0, "BLOCKED", str(e.detail))
            # If WAF detected an attack, block the IP immediately
            if "WAF Block" in str(e.detail):
                block_ip(client_ip, str(e.detail))
        raise e

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=8000, reload=True)
