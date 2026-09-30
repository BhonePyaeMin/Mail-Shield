"""Production WSGI entry point.

Used when MailShield is deployed behind a reverse proxy at a non-root
path (e.g. https://example.com/mailshield/) rather than run locally via
``python app.py``. Sets SCRIPT_NAME so Flask's url_for()/redirects and
the session cookie path are correct for the mounted subpath, and strips
the prefix from PATH_INFO before dispatching to the Flask app.

Run with a production WSGI server, e.g.:
    gunicorn -w 2 --timeout 60 -b 127.0.0.1:8001 wsgi:application
"""

import os

from app import app as flask_app

MOUNT_PREFIX = os.environ.get("MAILSHIELD_MOUNT_PREFIX", "/mailshield")

flask_app.config["APPLICATION_ROOT"] = MOUNT_PREFIX
flask_app.config["SESSION_COOKIE_PATH"] = MOUNT_PREFIX


class PrefixMiddleware:
    def __init__(self, wsgi_app, prefix):
        self.wsgi_app = wsgi_app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == self.prefix or path.startswith(self.prefix + "/"):
            environ["PATH_INFO"] = path[len(self.prefix):]
            environ["SCRIPT_NAME"] = self.prefix
            return self.wsgi_app(environ, start_response)
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not Found"]


application = PrefixMiddleware(flask_app, MOUNT_PREFIX)
