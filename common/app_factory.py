"""Creates Flask applications configured the same way for every service."""

from flask import Flask

from common.config import HOST, PORTS
from common.errors import register_error_handlers


def create_app(service_name):
    """Return a Flask app named after the service, with JSON errors and ordered JSON keys."""
    app = Flask(service_name)
    app.json.sort_keys = False
    register_error_handlers(app)
    return app


def run_service(app):
    """Start the app on the port assigned to its service name."""
    app.run(host=HOST, port=PORTS[app.name], debug=False, use_reloader=False, threaded=True)
