import httpx
import asyncio

async def debug_scan():
    url = "http://testphp.vulnweb.com/artists.php?artist=1"
    payload = "'"
    test_url = "http://testphp.vulnweb.com/artists.php?artist='"
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        print(f"Testing {test_url}...")
        resp = await client.get(test_url)
        print(f"Status: {resp.status_code}")
        print(f"Length: {len(resp.text)}")
        
        errors = [
            "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
            "warning: mysql", "unclosed quotation mark", "postgresql error",
            "db2strm", "sqlite3.error", "odbc drivers", "oracle error"
        ]
        
        text_lower = resp.text.lower()
        found_err = None
        for err in errors:
            if err in text_lower:
                found_err = err
                break
        
        if found_err:
            print(f"MATCHED ERROR: {found_err}")
            # Show a snippet
            idx = text_lower.find(found_err)
            print(f"Snippet: ...{resp.text[idx:idx+100]}...")
        else:
            print("NO ERROR MATCHED")
            print("First 200 chars of body:")
            print(resp.text[:200])

if __name__ == "__main__":
    asyncio.run(debug_scan())
