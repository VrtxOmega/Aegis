import json
import urllib.request
import asyncio
import websockets

async def get_logs():
    req = urllib.request.urlopen("http://127.0.0.1:9222/json")
    pages = json.loads(req.read())
    ws_url = pages[0]["webSocketDebuggerUrl"]
    
    async with websockets.connect(ws_url) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
        await ws.recv() # ignore context created
        
        await ws.send(json.dumps({"id": 2, "method": "Runtime.evaluate", "params": {"expression": "location.reload()"}}))
        
        for _ in range(20):
            try:
                res = await asyncio.wait_for(ws.recv(), timeout=1.0)
                msg = json.loads(res)
                if msg.get("method") == "Runtime.exceptionThrown":
                    print("EXCEPTION:", json.dumps(msg["params"]["exceptionDetails"]))
                elif msg.get("method") == "Runtime.consoleAPICalled":
                    if msg["params"]["args"]:
                        print("CONSOLE:", msg["params"]["args"][0].get("value"))
            except asyncio.TimeoutError:
                continue
        
asyncio.run(get_logs())
