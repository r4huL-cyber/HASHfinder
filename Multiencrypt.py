import base64
import codecs
import hashlib
import string
import time
import os
import pyfiglet
import os
from termcolor import cprint

cprint(title, "cyan")
cprint(author, "green")


def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 80)
    
    title = pyfiglet.figlet_format("Multi Encryptor", font="slant")
    author = pyfiglet.figlet_format("by R4HUL", font="digital")

    print(title)
    print(author)
    print("=" * 80)


# === Identifier Logic ===
def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

def is_base32(s):
    try:
        return base64.b32encode(base64.b32decode(s)) == s.encode()
    except Exception:
        return False

def is_rot13(s):
    decoded = codecs.encode(s, 'rot_13')
    return decoded.isprintable() and decoded != s

def is_sha256(s):
    return len(s) == 64 and all(c in string.hexdigits for c in s)

def is_caesar(s):
    return all(c.isalpha() or c.isspace() for c in s)

def identify_encryption(text):
    if is_sha256(text):
        return "SHA256 (likely hash, not reversible)"
    elif is_base64(text):
        return "Base64"
    elif is_base32(text):
        return "Base32"
    elif is_rot13(text):
        return "ROT13"
    elif is_caesar(text):
        return "Caesar Cipher (or plain text)"
    else:
        return "Unknown or Custom Encryption"

# === Run ===
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')  # Optional: clears terminal
    banner()
    
    input_text = input("🔹 Enter the encrypted text: ").strip()
    print("\n🔎 Identifying...\n")
    time.sleep(1)  # Simulate processing

    result = identify_encryption(input_text)
    print(f"✅ Detected as: {result}")

    print("\n" + "=" * 50)
    print("📦 Tool by R4HUL — Keep Encrypting Securely!")
    print("=" * 50)
