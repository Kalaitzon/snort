
"""
Simple victim HTTP server for the live mode (see traffic_gen.py).
It listens on 0.0.0.0:8080 and serves minimal content. It is only useful
as a target when traffic is generated live; it is not needed for the offline analysis.
"""
import http.server
import socketserver

PORT = 8080

class H(http.server.BaseHTTPRequestHandler):
    # Replies 200 OK with a minimal page on every GET
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Lab victim server</body></html>")

    def log_message(self, *a):   # silent logging (clean output)
        pass

if __name__ == "__main__":
    # TCPServer that serves indefinitely until Ctrl+C
    with socketserver.TCPServer(("", PORT), H) as httpd:
        print(f"[+] Victim server on http://0.0.0.0:{PORT}  (Ctrl+C to stop)")
        httpd.serve_forever()
