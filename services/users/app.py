"""Users and Identity Management Service (port 5001).

Developed by: Hassane El Khatib
"""

from flask import g, request

from common.app_factory import create_app, run_service
from common.auth import (
    check_password,
    create_token,
    deny,
    hash_password,
    optional_user,
    require_roles,
    require_service_or_roles,
)
from common.clients import log_event, notify
from common.config import JWT_EXPIRY_MINUTES
from common.constants import ACCOUNT_STATUSES, ADMIN, AUDITOR, REGULAR, ROLES
from common.errors import AuthError, ConflictError, ForbiddenError, NotFoundError, ValidationError
from common.responses import success
from common.validators import Validator
from services.users.repository import UserRepository

app = create_app("users")
users = UserRepository()

REGISTER_FIELDS = ["full_name", "username", "email", "password", "department", "role"]
SELF_UPDATABLE = ["full_name", "email", "department"]
ADMIN_UPDATABLE = SELF_UPDATABLE + ["role", "account_status"]


def find_user_or_404(user_id):
    """Return the user or raise NotFoundError."""
    user = users.get_by_id(user_id)
    if user is None:
        raise NotFoundError(f"User {user_id} not found")
    return user


@app.route("/users/register", methods=["POST"])
def register_user():
    """User Registration.

    Creates a new account. Anyone may register a Regular User account; only a
    Security Administrator (Bearer token) may create accounts with other roles.
    Developed by: Hassane El Khatib
    """
    caller = optional_user()
    data = Validator.body()
    Validator.require(data, REGISTER_FIELDS)

    full_name = Validator.text(data["full_name"], "full_name", 2, 100)
    username = Validator.username(data["username"])
    email = Validator.email(data["email"])
    password = Validator.password(data["password"])
    department = Validator.text(data["department"], "department", 2, 100)
    role = Validator.enum(data["role"], ROLES, "role")

    if role != REGULAR and (caller is None or caller["role"] != ADMIN):
        log_event(
            caller["user_id"] if caller else None,
            "UNAUTHORIZED_ACCESS",
            f"Attempt to register '{username}' with role {role} without administrator rights",
            "Warning",
            "users",
        )
        raise ForbiddenError(f"Only a Security Administrator can create accounts with role {role}")

    if users.username_taken(username):
        raise ConflictError(f"Username '{username}' is already taken")
    if users.email_taken(email):
        raise ConflictError(f"Email '{email}' is already registered")

    user_id = users.insert({
        "full_name": full_name,
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "department": department,
        "role": role,
        "account_status": "Active",
    })
    log_event(
        caller["user_id"] if caller else user_id,
        "USER_CREATED",
        f"User {username} (id {user_id}, {role}) registered",
        "Information",
        "users",
    )
    return success(users.get_by_id(user_id).to_dict(), "User registered successfully", 201)


@app.route("/users/login", methods=["POST"])
def login():
    """User Login.

    Verifies the username (or email) and password against the stored bcrypt hash
    and returns a JWT valid for JWT_EXPIRY_MINUTES. Inactive and suspended
    accounts are refused.
    Developed by: Hassane El Khatib
    """
    data = Validator.body()
    identifier = data.get("username") or data.get("email")
    if not identifier:
        Validator.require(data, ["username", "password"])
    Validator.require(data, ["password"])
    identifier = Validator.text(identifier, "username", 1, 120)
    password = data["password"]
    if not isinstance(password, str):
        raise ValidationError("password must be a string")

    user = users.get_by_login(identifier)
    if user is None or not check_password(password, user.password_hash):
        reason = "unknown username" if user is None else "wrong password"
        log_event(
            user.user_id if user else None,
            "LOGIN_FAILED",
            f"Failed login for '{identifier}': {reason}",
            "Warning",
            "users",
        )
        raise AuthError("Invalid username or password")

    if not user.is_active():
        log_event(
            user.user_id,
            "LOGIN_FAILED",
            f"Login refused for '{user.username}': account {user.account_status}",
            "Warning",
            "users",
        )
        raise ForbiddenError(f"Account is {user.account_status}. Contact a Security Administrator")

    users.touch_last_login(user.user_id)
    log_event(user.user_id, "LOGIN_SUCCESS", f"User {user.username} logged in", "Information", "users")
    token = create_token(user.user_id, user.username, user.role)
    return success(
        {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role,
            "expires_in_minutes": JWT_EXPIRY_MINUTES,
        },
        "Login successful",
        token=token,
    )


@app.route("/users/<int:user_id>", methods=["PUT"])
@require_roles(ADMIN, REGULAR)
def update_user(user_id):
    """Update User Information.

    Regular users may update their own full_name, email and department.
    Security Administrators may update any user, including role and account_status.
    Developed by: Hassane El Khatib
    """
    caller = g.user
    is_admin = caller["role"] == ADMIN
    if not is_admin and caller["user_id"] != user_id:
        deny("You can only update your own information")

    data = Validator.body()
    user = find_user_or_404(user_id)
    Validator.only_fields(data, ADMIN_UPDATABLE if is_admin else SELF_UPDATABLE)

    changes = {}
    if "full_name" in data:
        changes["full_name"] = Validator.text(data["full_name"], "full_name", 2, 100)
    if "email" in data:
        email = Validator.email(data["email"])
        if users.email_taken(email, exclude_id=user_id):
            raise ConflictError(f"Email '{email}' is already registered")
        changes["email"] = email
    if "department" in data:
        changes["department"] = Validator.text(data["department"], "department", 2, 100)
    if "role" in data:
        changes["role"] = Validator.enum(data["role"], ROLES, "role")
    if "account_status" in data:
        changes["account_status"] = Validator.enum(data["account_status"], ACCOUNT_STATUSES, "account_status")

    if user_id == caller["user_id"] and (
        changes.get("role", user.role) != user.role
        or changes.get("account_status", user.account_status) != user.account_status
    ):
        raise ValidationError("You cannot change your own role or account status")

    changed = {key: value for key, value in changes.items() if getattr(user, key) != value}
    if not changed:
        return success(user.to_dict(), "No changes were made")

    users.update(user_id, changed)
    summary = "; ".join(f"{key} {getattr(user, key)} -> {value}" for key, value in changed.items())
    log_event(caller["user_id"], "USER_UPDATED", f"User {user.username} (id {user_id}) updated: {summary}",
              "Information", "users")

    if "role" in changed:
        log_event(caller["user_id"], "ROLE_CHANGED",
                  f"Role of {user.username} changed from {user.role} to {changed['role']}", "Warning", "users")
        notify(user_id, "Your role was changed",
               f"Your role changed from {user.role} to {changed['role']}.", "System Notification", "Medium")
    if "account_status" in changed:
        log_event(caller["user_id"], "ACCOUNT_STATUS_CHANGED",
                  f"Account of {user.username} changed from {user.account_status} to {changed['account_status']}",
                  "Warning", "users")
        notify(user_id, "Your account status was changed",
               f"Your account status is now {changed['account_status']}.", "System Notification", "Medium")

    return success(users.get_by_id(user_id).to_dict(), "User updated successfully")


@app.route("/users/<int:user_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_user(user_id):
    """Delete User.

    Only a Security Administrator may delete accounts, and never their own.
    Developed by: Hassane El Khatib
    """
    user = find_user_or_404(user_id)
    if user_id == g.user["user_id"]:
        raise ValidationError("You cannot delete your own account")
    users.delete(user_id)
    log_event(g.user["user_id"], "USER_DELETED", f"User {user.username} (id {user_id}, {user.role}) deleted",
              "Warning", "users")
    return success(message=f"User {user.username} (id {user_id}) deleted successfully")


@app.route("/users", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def get_all_users():
    """Retrieve All Users.

    Returns every account without password hashes. Optional filters: role, account_status.
    Developed by: Hassane El Khatib
    """
    Validator.only_query(["role", "account_status"])
    filters = {}
    if "role" in request.args:
        filters["role"] = Validator.enum(request.args["role"], ROLES, "role")
    if "account_status" in request.args:
        filters["account_status"] = Validator.enum(request.args["account_status"], ACCOUNT_STATUSES,
                                                   "account_status")
    result = [user.to_dict() for user in users.search(exact=filters)]
    return success(result, "Users retrieved successfully")


@app.route("/users/<username>", methods=["GET"])
@require_roles(ADMIN, AUDITOR, REGULAR)
def get_user_by_username(username):
    """Retrieve User By Username.

    Administrators and auditors may look up anyone; regular users only themselves.
    Developed by: Hassane El Khatib
    """
    if g.user["role"] == REGULAR and g.user["username"] != username:
        deny("You can only view your own information")
    user = users.get_by_username(username)
    if user is None:
        raise NotFoundError(f"User '{username}' not found")
    return success(user.to_dict(), "User retrieved successfully")


@app.route("/internal/users/<int:user_id>", methods=["GET"])
@require_service_or_roles(ADMIN)
def internal_get_user(user_id):
    """Internal lookup of one user's id, name, role and status for other services.

    Developed by: Hassane El Khatib
    """
    return success(find_user_or_404(user_id).to_public_dict())


@app.route("/internal/users", methods=["GET"])
@require_service_or_roles(ADMIN)
def internal_users_by_role():
    """Internal list of users, optionally filtered by role, for other services.

    Developed by: Hassane El Khatib
    """
    Validator.only_query(["role"])
    filters = {}
    if "role" in request.args:
        filters["role"] = Validator.enum(request.args["role"], ROLES, "role")
    return success([user.to_public_dict() for user in users.search(exact=filters)])


if __name__ == "__main__":
    run_service(app)
