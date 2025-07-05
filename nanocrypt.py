import os
import sys
import argparse
from getpass import getpass
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet
from prompt_toolkit import Application
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit
from prompt_toolkit.widgets import TextArea, Frame
from prompt_toolkit.key_binding import KeyBindings

# === Encryption helpers ===

def derive_key(password: str, salt: bytes) -> bytes:
    key = pbkdf2_hmac('sha256', password.encode(), salt, 100_000, dklen=32)
    return urlsafe_b64encode(key)

def encrypt(content: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    return salt + Fernet(key).encrypt(content)

def decrypt(encrypted: bytes, password: str) -> bytes:
    salt = encrypted[:16]
    data = encrypted[16:]
    key = derive_key(password, salt)
    return Fernet(key).decrypt(data)

# === Editor ===

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

    @kb.add('tab')
    def _(event):
        if not readonly:
            event.app.current_buffer.insert_text(' ' * 4)

    @kb.add('c-a')
    def _(event):
        buf = event.app.current_buffer
        buf.cursor_position = 0
        buf.start_selection()
        buf.cursor_position = len(buf.text)

    @kb.add('left')
    @kb.add('right')
    @kb.add('up')
    @kb.add('down')
    def _(event):
        buf = event.app.current_buffer
        if buf.selection_state:
            buf.exit_selection()

    editor = TextArea(
        text=text,
        scrollbar=True,
        read_only=readonly,
        line_numbers=True,
    )

    # Cancel selection on mouse click
    original_mouse_handler = editor.control.mouse_handler

    def mouse_handler(mouse_event):
        buf = editor.buffer
        if buf.selection_state:
            buf.exit_selection()
        return original_mouse_handler(mouse_event)

    editor.control.mouse_handler = mouse_handler


    frame = Frame(
        title="Encrypted Nano Editor (Ctrl+S=Save, Ctrl+Q=Quit, Tab=Indent, Ctrl+A=Select All)",
        body=editor
    )

    layout = Layout(HSplit([frame]))

    app = Application(
        layout=layout,
        key_bindings=kb,
        full_screen=True,
        mouse_support=True
    )
    app.run()

    return saved_content["text"]

# === Main logic ===

def main():
    parser = argparse.ArgumentParser(description="Cross-platform nano-like encrypted editor")
    parser.add_argument("filename", help="File to open")
    parser.add_argument("--plaintext", action="store_true", help="Open file as plaintext (encrypt on save)")
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
                new_pw = getpass("Enter new password: ")
                confirm_pw = getpass("Confirm new password: ")
                if new_pw != confirm_pw:
                    print("[!] Passwords do not match.")
                    return
                password = new_pw
            encrypted = encrypt(edited_text.encode(), password)
            with open(filename, "wb") as f:
                f.write(encrypted)
            print(f"[+] File saved and encrypted: {filename}")

if __name__ == "__main__":
    main()
