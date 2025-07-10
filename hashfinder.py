import base64
import codecs
import hashlib
import string
import time
import os
import pyfiglet
import os






from termcolor import cprint

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 80)

    # Create banner text
    title = pyfiglet.figlet_format("HASH finder", font="slant")
    author = pyfiglet.figlet_format("by R4HUL", font="digital")

    # Define rainbow colors
    rainbow_colors = ["red", "yellow", "green", "cyan", "white", "magenta"]

    # Print title in rainbow style (line by line)
    for i, line in enumerate(title.split("\n")):
        if line.strip():
            cprint(line, rainbow_colors[i % len(rainbow_colors)], attrs=["bold"])

    # Print author with alternating color
    for i, line in enumerate(author.split("\n")):
        if line.strip():
            cprint(line, rainbow_colors[(i + 5) % len(rainbow_colors)], attrs=["bold"])

    cprint("=" * 80, "yellow", attrs=["bold"])



def is_md5(s): return len(s) == 32 and all(c in string.hexdigits for c in s)
def is_sha1(s): return len(s) == 40 and all(c in string.hexdigits for c in s)
def is_sha224(s): return len(s) == 56 and all(c in string.hexdigits for c in s)
def is_sha256(s): return len(s) == 64 and all(c in string.hexdigits for c in s)
def is_sha384(s): return len(s) == 96 and all(c in string.hexdigits for c in s)
def is_sha512(s): return len(s) == 128 and all(c in string.hexdigits for c in s)

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
    return decoded != s and decoded.isprintable()

def is_reverse(text):
    return text[::-1].isprintable() and text[::-1] != text

def is_atbash(text):
    def atbash(char):
        if char.isupper():
            return chr(65 + (25 - (ord(char) - 65)))
        elif char.islower():
            return chr(97 + (25 - (ord(char) - 97)))
        return char
    reversed_text = ''.join(atbash(c) for c in text)
    return reversed_text != text and reversed_text.isprintable()

def is_caesar(text):
    return all(c.isalpha() or c.isspace() for c in text)

# === Main Detection Function ===
def identify_encryption(text):
    if is_md5(text):
        return "MD5 (hash, not reversible)"
    elif is_sha1(text):
        return "SHA-1 (hash)"
    elif is_sha224(text):
        return "SHA-224 (hash)"
    elif is_sha256(text):
        return "SHA-256 (hash)"
    elif is_sha384(text):
        return "SHA-384 (hash)"
    elif is_sha512(text):
        return "SHA-512 (hash)"
    elif is_base64(text):
        return "Base64"
    elif is_base32(text):
        return "Base32"
    elif is_rot13(text):
        return "ROT13 (Caesar-13)"
    elif is_atbash(text):
        return "Atbash Cipher"
    elif is_reverse(text):
        return "Reversed Text"
    elif is_caesar(text):
        return "Caesar Cipher or Plain English"
    else:
        return "Unknown or Custom Encryption"

# === Run ===
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    
    input_text = input("🔹 Enter the encrypted text: ").strip()
    print("\n🔎 Identifying...\n")
    time.sleep(1)

    result = identify_encryption(input_text)
    print(f"✅ Detected as: {result}")

    
    cprint("=" * 80, "yellow", attrs=["bold"])
    cprint("📦 Tool by R4HUL — Keep Encrypting Securely!","red")
    cprint("=" * 80, "yellow", attrs=["bold"])
