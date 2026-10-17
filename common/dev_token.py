"""Print a valid test token for any role.

Usage: python -m common.dev_token "Security Analyst" 2 analyst1
"""

import sys

from common.auth import create_token
from common.constants import ADMIN, ROLES


def main():
    """Read role, user id and username from the command line and print a token."""
    role = sys.argv[1] if len(sys.argv) > 1 else ADMIN
    user_id = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    username = sys.argv[3] if len(sys.argv) > 3 else "dev_user"
    if role not in ROLES:
        sys.exit(f"Role must be one of: {', '.join(ROLES)}")
    print(create_token(user_id, username, role))


if __name__ == "__main__":
    main()
