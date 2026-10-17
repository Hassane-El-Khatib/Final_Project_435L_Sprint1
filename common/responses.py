"""Standard success and error response bodies."""

from flask import jsonify


def success(data=None, message=None, code=200, **extra):
    """Build ``{"status": "success", "message", "count", "data", ...}``."""
    body = {"status": "success"}
    if message:
        body["message"] = message
    if isinstance(data, list):
        body["count"] = len(data)
    body.update(extra)
    if data is not None:
        body["data"] = data
    return jsonify(body), code


def error(message, code, errors=None):
    """Build ``{"status": "error", "message", "errors"?}``."""
    body = {"status": "error", "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), code
