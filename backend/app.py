from fastapi import FastAPI, Request
import json

app = FastAPI(title="Mock Backend API")

@app.get("/")
async def root():
    return {"message": "Welcome to the Mock Backend API"}

@app.post("/api/data")
async def receive_data(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = (await request.body()).decode('utf-8')
    return {"status": "success", "received": payload}

@app.get("/api/users")
async def get_users():
    return [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
