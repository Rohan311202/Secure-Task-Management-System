
from getpass import getpass
from cryptography.exceptions import InvalidTag
from security import encrypt_task, decrypt_task

password = getpass("Enter a test password: ")

description = "Complete security report"
classification = "Top Secret"

encrypted = encrypt_task(
    password,
    description,
    classification
)

print("Encryption successful!")

decrypted = decrypt_task(password, encrypted)

assert decrypted["description"] == description
assert decrypted["classification"] == classification

print("Decryption successful!")
print("Original task details recovered correctly!")

try:
    decrypt_task(password + "wrong", encrypted)
except InvalidTag:
    print("Incorrect password rejected successfully!")
else:
    print("ERROR: Incorrect password was accepted!")
