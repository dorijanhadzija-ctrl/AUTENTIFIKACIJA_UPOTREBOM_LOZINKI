
import sys
import json
import os
import hashlib
import getpass

DB_FILE = "users.json"
ITERATIONS = 200_000


def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        ITERATIONS
    ).hex()


def add_user(username):
    db = load_db()
    if username in db:
        print("User already exists.")
        return

    pw1 = getpass.getpass("Password: ")
    pw2 = getpass.getpass("Repeat Password: ")

    if pw1 != pw2:
        print("User add failed. Password mismatch.")
        return

    salt = os.urandom(16)
    db[username] = {
        "salt": salt.hex(),
        "hash": hash_password(pw1, salt),
        "force_change": False
    }

    save_db(db)
    print("User successfully added.")


def change_password(username):
    db = load_db()
    if username not in db:
        print("Password change failed.")
        return

    pw1 = getpass.getpass("Password: ")
    pw2 = getpass.getpass("Repeat Password: ")

    if pw1 != pw2:
        print("Password change failed. Password mismatch.")
        return

    salt = os.urandom(16)
    db[username]["salt"] = salt.hex()
    db[username]["hash"] = hash_password(pw1, salt)
    db[username]["force_change"] = False

    save_db(db)
    print("Password change successful.")


def force_pass(username):
    db = load_db()
    if username not in db:
        print("User not found.")
        return

    db[username]["force_change"] = True
    save_db(db)
    print("User will be requested to change password on next login.")


def delete_user(username):
    db = load_db()
    if username not in db:
        print("User not found.")
        return

    del db[username]
    save_db(db)
    print("User successfully removed.")


def main():
    if len(sys.argv) < 3:
        print("Usage: usermgmt <add|passwd|forcepass|del> <username>")
        return

    cmd = sys.argv[1]
    username = sys.argv[2]

    if cmd == "add":
        add_user(username)
    elif cmd == "passwd":
        change_password(username)
    elif cmd == "forcepass":
        force_pass(username)
    elif cmd == "del":
        delete_user(username)
    else:
        print("Unknown command.")


if __name__ == "__main__":
    main()
