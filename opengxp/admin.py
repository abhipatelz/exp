"""Administrative CLI: python -m opengxp.admin DB create-user USERNAME "FULL NAME" ROLE[,ROLE...]"""
import getpass
import sys

from . import open_system


def main():
    if len(sys.argv) != 6 or sys.argv[2] != "create-user":
        sys.exit(__doc__)
    db, _, username, full_name, roles = sys.argv[1:]
    password = getpass.getpass(f"Password for {username}: ")
    open_system(db).create_user(username, full_name, roles.split(","), password, actor="admin-cli")
    print(f"created {username}")


if __name__ == "__main__":
    main()
