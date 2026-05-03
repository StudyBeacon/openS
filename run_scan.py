import asyncio
import json
from backend.live_scanner import LiveScanner

async def run_test():
    url = "http://127.0.0.1:5000/?artist=1"
    scanner = LiveScanner(url, depth=1)
    try:
        report = await scanner.scan()
        print("\n" + "="*50)
        print("SCAN REPORT")
        print("="*50)
        print(json.dumps(report, indent=2))
    finally:
        await scanner.close()

if __name__ == "__main__":
    asyncio.run(run_test())
