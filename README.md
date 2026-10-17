# Security Incident Detection and Response Management System

Backend for EECE 435L (Software Tools Lab), Sprint I. Nine independent Flask REST services share one SQLite database and talk to each other over HTTP.

**Team:** Hassane El Khatib, Yehia Afesh, Abdul Rahman Habbal

## Services

| Service | Folder | Port | Developed by |
| --- | --- | --- | --- |
| Users & Identity | `services/users` | 5001 | Hassane El Khatib |
| Assets | `services/assets` | 5002 | Yehia Afesh |
| Incidents | `services/incidents` | 5003 | Yehia Afesh |
| Threat Intelligence | `services/threats` | 5004 | Abdul Rahman Habbal |
| Audit Logging | `services/logs` | 5005 | Hassane El Khatib |
| Reports | `services/reports` | 5006 | Abdul Rahman Habbal |
| Vulnerabilities | `services/vulnerabilities` | 5007 | Yehia Afesh |
| Notifications | `services/notifications` | 5008 | Hassane El Khatib |
| Playbooks (and `/actions`) | `services/playbooks` | 5009 | Abdul Rahman Habbal |

Shared work: the `common/` package, database setup and `main.py` (Hassane El Khatib); database design and ERD (Yehia Afesh); final Postman collection and report assembly (Abdul Rahman Habbal).

Postman: each service has its own folder in `postman/Sprint1.postman_collection.json`, and every request name starts with the full name of the student who developed that API.

## Setup (Ubuntu)

```bash
sudo apt install python3 python3-venv python3-pip git
git clone https://github.com/Hassane-El-Khatib/Final_Project_435L_Sprint1.git
cd Sprint1
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m database.init_db --reset
python main.py
```

`main.py` starts every service that has an `app.py` and stops them all with Ctrl+C. Rebuild the database at any time with `python -m database.init_db --reset`.

## Test accounts (created by `init_db`)

| id | username | password | role | status |
| --- | --- | --- | --- | --- |
| 1 | admin | Admin@1234 | Security Administrator | Active |
| 2 | analyst1 | Analyst@1234 | Security Analyst | Active |
| 3 | analyst2 | Analyst@1234 | Security Analyst | Active |
| 4 | employee1 | Employee@1234 | Regular User | Active |
| 5 | employee2 | Employee@1234 | Regular User | Active |
| 6 | auditor1 | Auditor@1234 | Auditor | Active |
| 7 | suspended1 | Employee@1234 | Regular User | Suspended |
| 8 | inactive1 | Employee@1234 | Regular User | Inactive |

## Postman

Import `postman/Sprint1.postman_collection.json` and `postman/Sprint1_Local.postman_environment.json`, select the **Sprint1_Local** environment, run the **00 Auth helpers** folder, then the other folders in order.

## Conventions

- Success: `{"status": "success", "message": ..., "count"?: n, "data": ...}`; error: `{"status": "error", "message": ...}`.
- Status codes: 400 validation, 401 authentication, 403 permission, 404 not found, 409 conflict, 500 server error.
- Every protected route uses `@require_roles(...)`; every create/update/delete calls `log_event(...)`.
- All SQL uses `?` parameters through `BaseRepository`.
- Every route docstring ends with `Developed by: <Full Name>`.

## Adding a service

Each service folder contains `__init__.py`, `models.py`, `repository.py` and `app.py`.

```python
from flask import g

from common.app_factory import create_app, run_service
from common.auth import require_roles
from common.clients import log_event, notify, notify_role, get_user
from common.constants import ADMIN, ANALYST, AUDITOR, SEVERITIES
from common.errors import NotFoundError, ValidationError, ConflictError
from common.responses import success
from common.validators import Validator

app = create_app("assets")


@app.route("/assets", methods=["POST"])
@require_roles(ADMIN)
def create_asset():
    """Add New Asset.

    Developed by: <Full Name>
    """
    data = Validator.body()
    Validator.require(data, ["asset_name", "asset_type", "ip_address"])
    ...
    log_event(g.user["user_id"], "ASSET_CREATED", "Asset 9 VPN-GW-01 created", "Information", "assets")
    return success(asset.to_dict(), "Asset created successfully", 201)


if __name__ == "__main__":
    run_service(app)
```

Shared helpers:

| Helper | Use |
| --- | --- |
| `create_app(name)` / `run_service(app)` | App with JSON errors; runs on the port from `common/config.py` |
| `@require_roles(ADMIN, ...)` | 401 without a valid token, 403 for other roles (both logged); sets `g.user` (`user_id`, `username`, `role`) |
| `deny(message)` | Log and raise 403 for ownership rules ("only your own ...") |
| `Validator.body/require/text/enum/ip/integer/number/date/only_fields/only_query/query_integer/transition` | Input validation, raises 400 |
| `BaseRepository` | Subclass with `table`, `id_column`, `columns`, `model`; gives `get_by_id`, `get_all`, `exists`, `insert`, `update`, `delete`, `search`, `fetch_one`, `fetch_all`, `fetch_value` |
| `log_event(user_id, action, description, severity, service)` | Audit log through the Logs service |
| `notify(user_id, title, message, type, severity)` / `notify_role(role, ...)` | Notifications |
| `get_user(user_id)` | User details from the Users service (`None` if missing) |
| `python -m common.dev_token "Security Analyst" 2 analyst1` | Test token without logging in |

Add your tables to `database/schema.sql` and your demo rows to `database/seed.sql` (explicit ids), then run `python -m database.init_db --reset`.
