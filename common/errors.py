"""Exception hierarchy and global error handlers shared by every service."""

from flask import current_app
from werkzeug.exceptions import HTTPException

from common.responses import error


class ApiError(Exception):
    """Base class for every error that should be returned to the client as JSON."""

    status_code = 400

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.message = message
        self.errors = errors


class ValidationError(ApiError):
    """Invalid, missing or malformed input (400)."""

    status_code = 400


class AuthError(ApiError):
    """Missing or invalid credentials or token (401)."""

    status_code = 401


class ForbiddenError(ApiError):
    """Authenticated but not allowed to perform the operation (403)."""

    status_code = 403


class NotFoundError(ApiError):
    """The requested record does not exist (404)."""

    status_code = 404


class ConflictError(ApiError):
    """Duplicate data or an operation blocked by related records (409)."""

    status_code = 409


class ServiceUnavailableError(ApiError):
    """Another service needed to complete the request could not be reached (503)."""

    status_code = 503


HTTP_MESSAGES = {
    400: "Malformed request body",
    404: "Route not found",
    405: "Method not allowed on this endpoint",
    415: "Content-Type must be application/json",
}


def register_error_handlers(app):
    """Make every service return the same JSON error format."""

    @app.errorhandler(ApiError)
    def handle_api_error(exc):
        return error(exc.message, exc.status_code, exc.errors)

    @app.errorhandler(HTTPException)
    def handle_http_error(exc):
        return error(HTTP_MESSAGES.get(exc.code, exc.description), exc.code)

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc):
        current_app.logger.exception(exc)
        return error("Internal server error", 500)
