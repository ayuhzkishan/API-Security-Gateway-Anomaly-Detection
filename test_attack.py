import httpx
import asyncio

async def run_attacks():
    print("🚀 Starting Security Gateway Tests...")
    async with httpx.AsyncClient() as client:
        # 1. Get Token
        print("\n[+] Getting JWT Token...")
        res = await client.get("http://localhost:8000/token")
        if res.status_code != 200:
            print("Failed to get token:", res.text)
            return
        token = res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Normal Request
        print("\n[+] Sending Normal Request (/api/users)...")
        res = await client.get("http://localhost:8000/api/users", headers=headers)
        print(f"Status: {res.status_code}, Response: {res.text[:100]}")
        
        # 3. WAF SQLi Test
        print("\n[+] Sending SQLi Attack (query param)...")
        # We might be blocked already? Wait, IP blocking logic might block us permanently after WAF fail.
        # Let's see if we get a 403.
        res = await client.get("http://localhost:8000/api/users?id=1' OR '1'='1", headers=headers)
        print(f"Status: {res.status_code}, Response: {res.text[:100]}")
        
        # 4. WAF XSS Test
        print("\n[+] Sending XSS Attack (body post)...")
        res = await client.post("http://localhost:8000/api/data", json={"content": "<script>alert(1)</script>"}, headers=headers)
        print(f"Status: {res.status_code}, Response: {res.text[:100]}")
        
        # 5. ML Anomaly: Huge Payload
        print("\n[+] Sending Anomalous Request (Massive Payload > ML norm)...")
        huge_payload = {"data": "X" * 10000}
        res = await client.post("http://localhost:8000/api/data", json=huge_payload, headers=headers)
        print(f"Status: {res.status_code}, Response: {res.text[:100]}")
        
        # 6. Rate Limit Test
        print("\n[+] Testing Rate Limit (Sending 65 logic requests very fast)...")
        for i in range(65):
            res = await client.get("http://localhost:8000/", headers=headers)
            if res.status_code == 429:
                print(f"Rate limited at request {i+1}")
                break

if __name__ == "__main__":
    asyncio.run(run_attacks())
