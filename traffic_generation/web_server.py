# Ioannis Kalaitzidis, MTE25012

"""
Απλος HTTP server-θυμα για το live mode (βλ. traffic_gen.py).
Ακουει στο 0.0.0.0:8080 και εξυπηρετει ελαχιστο περιεχομενο. Χρησιμευει μονο
ως στοχος οταν η κινηση παραγεται ζωντανα, δεν χρειαζεται για την offline αναλυση.
"""
import http.server
import socketserver

PORT = 8080

class H(http.server.BaseHTTPRequestHandler):
    # Απανταει 200 OK με μια ελαχιστη σελιδα σε καθε GET
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Lab victim server</body></html>")

    def log_message(self, *a):   # σιωπηλο logging (καθαρη εξοδος)
        pass

if __name__ == "__main__":
    # TCPServer που εξυπηρετει επ' αοριστον μεχρι Ctrl+C
    with socketserver.TCPServer(("", PORT), H) as httpd:
        print(f"[+] Victim server on http://0.0.0.0:{PORT}  (Ctrl+C to stop)")
        httpd.serve_forever()
