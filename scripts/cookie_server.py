from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"""<!doctype html><html><head><title>loading</title></head><body>
<script>
document.cookie = 'cloudbrowser_js=persisted; max-age=86400; path=/; samesite=lax';
localStorage.setItem('cloudbrowser_state', 'persisted');
document.title = localStorage.getItem('cloudbrowser_state');
</script>ok</body></html>"""
        self.send_response(200)
        if self.path.startswith("/set"):
            self.send_header(
                "Set-Cookie", "cloudbrowser=persisted; Max-Age=86400; Path=/; SameSite=Lax"
            )
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)


ThreadingHTTPServer(("0.0.0.0", 18080), Handler).serve_forever()
