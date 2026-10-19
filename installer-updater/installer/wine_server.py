"""Static files with HTTP Range for the Wine installer test; runs with Linux python3 inside WSL (Wine reaches it).

  python3 wine_server.py <port>=<folder> [<port>=<folder> ...]

A folder of "-" answers 404 to everything (a game file source that is gone). Prints "ready" when listening.
"""
import functools
import http.server
import sys
import threading
from pathlib import Path


class Files(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_head(self):
        if self.directory == '-':
            self.send_error(404)
            return None
        path = Path(self.translate_path(self.path))
        header = self.headers.get('Range')
        if not header or not path.is_file():
            return super().send_head()
        start = int(header.split('=')[1].split('-')[0])
        size = path.stat().st_size
        if start >= size:
            self.send_response(416)
            self.send_header('Content-Range', f'bytes */{size}')
            self.end_headers()
            return None
        stream = open(path, 'rb')
        stream.seek(start)
        self.send_response(206)
        self.send_header('Content-Range', f'bytes {start}-{size - 1}/{size}')
        self.send_header('Content-Length', str(size - start))
        self.end_headers()
        return stream


def main():
    servers = []
    for item in sys.argv[1:]:
        port, folder = item.split('=', 1)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', int(port)), functools.partial(Files, directory=folder))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    print('ready', flush=True)
    sys.stdin.read()  # Runs until the test closes stdin.


if __name__ == '__main__':
    main()
