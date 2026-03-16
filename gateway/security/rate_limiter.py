from fastapi import Request, HTTPException
import time

# Simple in-memory sliding window rate limiter
# Structure: { ip: [timestamp1, timestamp2, ...] }
RATE_LIMIT_STORE = {}
REQUESTS_PER_MINUTE = 60

def check_rate_limit(request: Request):
    # Fallback to "unknown" if request.client is None
    client_ip = request.client.host if request.client else "unknown"
    current_time = time.time()
    
    if client_ip not in RATE_LIMIT_STORE:
        RATE_LIMIT_STORE[client_ip] = []
        
    # Remove timestamps older than 60 seconds
    RATE_LIMIT_STORE[client_ip] = [ts for ts in RATE_LIMIT_STORE[client_ip] if current_time - ts < 60]
    
    if len(RATE_LIMIT_STORE[client_ip]) >= REQUESTS_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Too Many Requests")
        
    RATE_LIMIT_STORE[client_ip].append(current_time)
