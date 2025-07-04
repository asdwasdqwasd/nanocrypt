import sys
import os
from getpass import getpass
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.application import Application
from prompt_toolkit.layout import Layout
from prompt_toolkit.widgets import TextArea, Frame
from prompt_toolkit.layout.containers import HSplit
import argparse

# === Encryption utilities ===
def derive_key(password: str, salt: bytes) -> bytes:
    key = pbkdf2_hmac('sha256', password.encode(), salt, 100_000, dklen=32)
    return urlsafe_b64encode(key)

def encrypt(content: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(content)
    return salt + encrypted

def decrypt(encrypted: bytes, password: str) -> bytes:
    salt = encrypted[:16]
    data = encrypted[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(data)

# === Nano-like editor ===
def run_editor(text: str, readonly: bool):
    kb = KeyBindings()
    saved_content = {"text": None}

    @kb.add('c-s')
    def _(event):
        if readonly:
            return
        saved_content["text"] = editor.text
        app.exit()

    @kb.add('c-q')
    def _(event):
        app.exit()

    editor = TextArea(
        text=text,
        scrollbar=True,
        read_only=readonly,
        line_numbers=True,
    )

    frame = Frame(title="Encrypted Nano Editor (Ctrl+S=Save, Ctrl+Q=Quit)", body=editor)

    root_container = HSplit([frame])
    layout = Layout(root_container)

    app = Application(
        layout=layout,
        key_bindings=kb,
        full_screen=True
    )
    app.run()

    return saved_content["text"]

def main():
    parser = argparse.ArgumentParser(description="Cross-platform nano-like encrypted editor")
    parser.add_argument("filename", help="File to open")
    parser.add_argument("--plaintext", action="store_true", help="Open file as plaintext (encrypt after save)")
    parser.add_argument("--readonly", action="store_true", help="Open in read-only mode")
    parser.add_argument("--changepw", action="store_true", help="Change password on save (encrypted only)")
    args = parser.parse_args()

    filename = args.filename
    is_plain = args.plaintext
    is_readonly = args.readonly
    change_pw = args.changepw

    if is_plain:
        initial_text = ""
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                initial_text = f.read()
        edited_text = run_editor(initial_text, is_readonly)
        if edited_text is not None and not is_readonly:
            password = getpass("Enter password to encrypt this file: ")
            confirm = getpass("Confirm password: ")
            if password != confirm:
                print("[!] Passwords do not match.")
                return
            encrypted = encrypt(edited_text.encode(), password)
            with open(filename, "wb") as f:
                f.write(encrypted)
            print(f"[+] File encrypted and saved: {filename}")
    else:
        password = getpass("Enter password: ")
        if os.path.exists(filename):
            try:
                with open(filename, "rb") as f:
                    encrypted = f.read()
                    initial_text = decrypt(encrypted, password).decode()
            except Exception as e:
                print("[!] Error: wrong password or corrupted file.")
                return
        else:
            initial_text = ""

        edited_text = run_editor(initial_text, is_readonly)
        if edited_text is not None and not is_readonly:
            if change_pw:
                newpw = getpass("Enter new password: ")
                confpw = getpass("Confirm new password: ")
                if newpw != confpw:
                    print("[!] Passwords do not match.")
                    return
                password = newpw
            encrypted = encrypt(edited_text.encode(), password)
            with open(filename, "wb") as f:
                f.write(encrypted)
            print(f"[+] Saved and encrypted: {filename}")

if __name__ == "__main__":
    main()
