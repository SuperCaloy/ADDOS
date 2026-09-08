# Standalone entrypoint for launching the frontend web dashboard and local browser interface.
# Boots the Uvicorn ASGI server and spawns a background thread to automatically open the dashboard.
import threading
import time
import webbrowser
import uvicorn
from frontend.app import create_app

HOST = "127.0.0.1"
PORT = 8080


# Pauses briefly to allow the ASGI server to bind its network port before launching the default browser.
# Ensures the user interface opens only after the HTTP service is ready to accept connections.
def _open_browser():
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}")


# Starts the background browser launcher thread and runs the Uvicorn web server on the configured address.
if __name__ == "__main__":
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(create_app(), host=HOST, port=PORT)