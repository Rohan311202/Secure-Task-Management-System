
import argparse
import base64
import bcrypt
import hashlib
import hmac
import json
import os
import secrets
import uuid

from datetime import date, datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#

ACCOUNTS_FILE = Path(__file__).with_name("accounts.json")
TASKS_FILE = Path(__file__).with_name("tasks.json")
TOKENS_FILE = Path(__file__).with_name("tokens.json")




def load_records(path):
    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError(f"Invalid data format: {path.name}")

    return records


def save_records(path, records):
    temporary = path.with_name(path.name + ".tmp")

    with open(temporary, "w", encoding="utf-8") as file:
        json.dump(records, file, indent=4)

    os.replace(temporary, path)



# USER CLASS


class User:
    def __init__(
        self,
        agent_id,
        username,
        password,
        authorisation_level="agent"
    ):
        self.agent_id = agent_id
        self.username = username

        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        self.encrypted_tasks = []
        self.authorisation_level = authorisation_level

    def verify_password(self, password):
        return bcrypt.checkpw(
            password.encode("utf-8"),
            self.password_hash.encode("utf-8")
        )


def valid_password(password):
    size = len(password.encode("utf-8"))
    return len(password) >= 12 and size <= 72


def verify_account_password(account, password):
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            account["password_hash"].encode("utf-8")
        )
    except ValueError:
        return False



def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )

    return kdf.derive(password.encode("utf-8"))


def generate_salt():
    return os.urandom(16)


def encrypt_task(password, description, classification):
    salt = generate_salt()
    key = derive_key(password, salt)
    nonce = os.urandom(12)

    task_data = {
        "description": description,
        "classification": classification
    }

    plaintext = json.dumps(task_data).encode("utf-8")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }


def decrypt_task(password, encrypted_task):
    salt = base64.b64decode(encrypted_task["salt"])
    nonce = base64.b64decode(encrypted_task["nonce"])
    ciphertext = base64.b64decode(
        encrypted_task["ciphertext"]
    )

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode("utf-8"))



# ACCOUNT REGISTRATION


def create_account(role="agent"):
    accounts = load_records(ACCOUNTS_FILE)

    agent_id = input("Enter Agent ID: ").strip()
    username = input("Enter Username: ").strip()

    if not agent_id or not username:
        print("Agent ID and username cannot be empty.")
        return

    for account in accounts:
        if account["agent_id"] == agent_id:
            print("Agent ID already registered!")
            return

        if account["username"] == username:
            print("Username already exists!")
            return

    password = getpass("Enter Password: ")
    confirmation = getpass("Confirm Password: ")

    if password != confirmation:
        print("Passwords do not match!")
        return

    if not valid_password(password):
        print("Password must be at least 12 characters and at most 72 bytes.")
        return

    user = User(agent_id, username, password, role)

    accounts.append({
        "agent_id": user.agent_id,
        "username": user.username,
        "password_hash": user.password_hash,
        "authorisation_level": user.authorisation_level
    })

    save_records(ACCOUNTS_FILE, accounts)
    print("Account created successfully!")


def register_agent():
    create_account("agent")


def setup_admin():
    accounts = load_records(ACCOUNTS_FILE)

    if any(
        account.get("authorisation_level") == "admin"
        for account in accounts
    ):
        print("An administrator already exists.")
        return

    print("\n===== INITIAL ADMINISTRATOR SETUP =====")
    print("Use only during trusted initial setup.")
    create_account("admin")



# LOGIN


def login_agent():
    accounts = load_records(ACCOUNTS_FILE)

    if not accounts:
        print("No registered accounts found.")
        return None

    username = input("Enter Username: ").strip()
    password = getpass("Enter Password: ")

    for account in accounts:
        if account["username"] == username:
            if verify_account_password(account, password):
                print("Login successful!")
                return account
            break

    print("Invalid username or password!")
    return None





def add_task(agent_id, password):
    description = input("Enter Task Description: ").strip()
    due_date = input("Enter Due Date (YYYY-MM-DD): ").strip()

    print("\nClassification Levels:")
    print("1. Top Secret")
    print("2. Secret")
    print("3. Confidential")

    choice = input("Choose Classification (1-3): ").strip()

    classifications = {
        "1": "Top Secret",
        "2": "Secret",
        "3": "Confidential"
    }

    if not description:
        print("Task description cannot be empty!")
        return

    try:
        date.fromisoformat(due_date)
    except ValueError:
        print("Invalid date! Use YYYY-MM-DD.")
        return

    if choice not in classifications:
        print("Invalid classification!")
        return

    encrypted_data = encrypt_task(
        password,
        description,
        classifications[choice]
    )

    tasks = load_records(TASKS_FILE)

    tasks.append({
        "task_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "due_date": due_date,
        "encrypted_details": encrypted_data
    })

    save_records(TASKS_FILE, tasks)

    print("Task encrypted and saved successfully!")



# VIEW REDACTED TASKS


def view_tasks(agent_id):
    tasks = load_records(TASKS_FILE)

    agent_tasks = [
        task for task in tasks
        if task["agent_id"] == agent_id
    ]

    if not agent_tasks:
        print("You have no tasks.")
        return

    print("\n===== YOUR TASKS =====")

    for task in agent_tasks:
        print("\n------------------------")
        print("Task ID:", task["task_id"])
        print("Due Date:", task["due_date"])
        print("Description: [REDACTED]")
        print("Classification: [REDACTED]")

    print("\nTotal Tasks:", len(agent_tasks))




def hash_code(code):
    return hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()


def issue_security_code(admin_account):
    if admin_account.get("authorisation_level") != "admin":
        print("Access denied.")
        return

    password = getpass("Confirm administrator password: ")

    if not verify_account_password(admin_account, password):
        print("Authentication failed!")
        return

    agent_id = input("Enter Agent ID: ").strip()
    accounts = load_records(ACCOUNTS_FILE)

    target = next(
        (
            account for account in accounts
            if account["agent_id"] == agent_id
            and account["authorisation_level"] == "agent"
        ),
        None
    )

    if target is None:
        print("Agent not found.")
        return

    code = secrets.token_urlsafe(24)

    expires = datetime.now(timezone.utc) + timedelta(
        minutes=10
    )

    tokens = load_records(TOKENS_FILE)

    # Invalidate older codes for this agent.
    tokens = [
        token for token in tokens
        if token["agent_id"] != agent_id
    ]

    tokens.append({
        "agent_id": agent_id,
        "code_hash": hash_code(code),
        "expires_at": expires.isoformat()
    })

    save_records(TOKENS_FILE, tokens)

    print("\n===== SECURITY CODE ISSUED =====")
    print("Agent ID:", agent_id)
    print("One-time code:", code)
    print("Expires in: 10 minutes")
    print("Provide this code privately to the agent.")
    print("The code will not be shown again.")


def consume_security_code(agent_id, supplied_code):
    tokens = load_records(TOKENS_FILE)
    now = datetime.now(timezone.utc)

    supplied_hash = hash_code(supplied_code)

    for index, token in enumerate(tokens):
        if token["agent_id"] != agent_id:
            continue

        expiry = datetime.fromisoformat(
            token["expires_at"]
        )

        if now >= expiry:
            return False

        if hmac.compare_digest(
            supplied_hash,
            token["code_hash"]
        ):
            tokens.pop(index)
            save_records(TOKENS_FILE, tokens)
            return True

    return False




def view_sensitive_task(account):
    agent_id = account["agent_id"]
    tasks = load_records(TASKS_FILE)

    task_id = input("Enter Task ID: ").strip()

    task = next(
        (
            item for item in tasks
            if item["task_id"] == task_id
            and item["agent_id"] == agent_id
        ),
        None
    )

    if task is None:
        print("Task not found or access denied.")
        return

    password = getpass("Confirm your password: ")

    if not verify_account_password(account, password):
        print("Authentication failed!")
        return

    security_code = getpass("Enter agency security code: ")

    if not security_code:
        print("Security code required.")
        return

    try:
        details = decrypt_task(
            password,
            task["encrypted_details"]
        )
    except (InvalidTag, ValueError, KeyError):
        print("Unable to decrypt task.")
        return

    if not consume_security_code(agent_id, security_code):
        print("Invalid, expired, or already used security code.")
        return

    print("\n===== DECRYPTED TASK DETAILS =====")
    print("Task ID:", task["task_id"])
    print("Due Date:", task["due_date"])
    print("Description:", details["description"])
    print("Classification:", details["classification"])
    print("\nSecurity code consumed successfully.")




def agent_menu(account):
    while True:
        print("\n===== AGENT DASHBOARD =====")
        print("1. Add New Task")
        print("2. View My Tasks (Redacted)")
        print("3. View Sensitive Task Details")
        print("4. Logout")

        choice = input("Choose an option (1-4): ").strip()

        if choice == "1":
            password = getpass("Confirm your password: ")

            if verify_account_password(account, password):
                add_task(account["agent_id"], password)
            else:
                print("Authentication failed!")

        elif choice == "2":
            view_tasks(account["agent_id"])

        elif choice == "3":
            view_sensitive_task(account)

        elif choice == "4":
            print("Logged out successfully!")
            break

        else:
            print("Invalid option!")


def admin_menu(account):
    while True:
        print("\n===== ADMINISTRATOR DASHBOARD =====")
        print("1. Issue One-Time Security Code")
        print("2. Logout")

        choice = input("Choose an option (1-2): ").strip()

        if choice == "1":
            issue_security_code(account)

        elif choice == "2":
            print("Administrator logged out.")
            break

        else:
            print("Invalid option!")



def main():
    while True:
        print("\n===== SECURE TASK MANAGEMENT SYSTEM =====")
        print("1. Register Agent")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            register_agent()

        elif choice == "2":
            account = login_agent()

            if account is not None:
                if account["authorisation_level"] == "admin":
                    admin_menu(account)
                else:
                    agent_menu(account)

        elif choice == "3":
            print("Exiting system. Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Secure Task Management System"
    )

    parser.add_argument(
        "--setup-admin",
        action="store_true",
        help="Create the initial administrator account"
    )

    args = parser.parse_args()

    if args.setup_admin:
        setup_admin()
    else:
        main()
