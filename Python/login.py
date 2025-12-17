
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


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        ITERATIONS
    ).hex()


def login(username):
    db = load_db()
    password = getpass.getpass("Password: ")

    if username not in db:
        print("Username or password incorrect.")
        return

    user = db[username]
    salt = bytes.fromhex(user["salt"])
    hashed = hash_password(password, salt)

    if hashed != user["hash"]:
        print("Username or password incorrect.")
        return

    if user["force_change"]:
        new1 = getpass.getpass("New password: ")
        new2 = getpass.getpass("Repeat new password: ")

        if new1 != new2:
            print("Password change failed.")
            return

        new_salt = os.urandom(16)
        user["salt"] = new_salt.hex()
        user["hash"] = hash_password(new1, new_salt)
        user["force_change"] = False

        with open(DB_FILE, "w") as f:
            json.dump(db, f, indent=4)

    print("Login successful.")


def main():
    if len(os.sys.argv) != 2:
        print("Usage: login <username>")
        return

    login(os.sys.argv[1])


if __name__ == "__main__":
    main()
