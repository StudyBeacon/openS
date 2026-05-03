from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def home(artist: str = None):
    html = "<html><body><h1>Artist</h1>"
    if artist:
        # Mock SQLi reflection or error
        if "'" in artist:
            html += "<p>Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/artists.php on line 62</p>"
        else:
            html += f"<p>Artist: {artist}</p>"
        
        # Mock XSS reflection
        html += f"<div>You searched for: {artist}</div>"
    
    html += "</body></html>"
    return html

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
