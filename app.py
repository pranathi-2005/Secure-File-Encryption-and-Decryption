import os
import base64
import hashlib
from tkinter import *
from tkinter import filedialog
from cryptography.fernet import Fernet

# Generate key from password
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Encrypt file
def encrypt_file(file_path, password):
    key = generate_key(password)
    fernet = Fernet(key)

    try:
        with open(file_path, 'rb') as file:
            original = file.read()
    except FileNotFoundError:
        status_var.set("❌ File not found.")
        return

    encrypted = fernet.encrypt(original)
    encrypted_path = file_path + '.encrypted'

    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    status_var.set(f"✅ File encrypted and saved as: {encrypted_path}")

# Decrypt file
def decrypt_file(encrypted_file_path, password):
    key = generate_key(password)
    fernet = Fernet(key)

    try:
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
    except FileNotFoundError:
        status_var.set("❌ Encrypted file not found.")
        return

    try:
        decrypted = fernet.decrypt(encrypted_data)
    except Exception:
        status_var.set("❌ Invalid password or corrupted file.")
        return

    decrypted_path = encrypted_file_path.replace('.encrypted', '.decrypted')

    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted)

    status_var.set(f"✅ File decrypted and saved as: {decrypted_path}")

# File selection
def choose_file():
    file_path = filedialog.askopenfilename()
    file_path_var.set(file_path)

# Encrypt action
def do_encrypt():
    password = encrypt_password_entry.get()
    file_path = file_path_var.get()
    if not file_path or not password:
        status_var.set("❌ Please select a file and enter a password.")
        return
    encrypt_file(file_path, password)

# Decrypt action
def do_decrypt():
    password = decrypt_password_entry.get()
    file_path = file_path_var.get()
    if not file_path or not password:
        status_var.set("❌ Please select a file and enter a password.")
        return
    decrypt_file(file_path, password)

# --- GUI Setup ---
root = Tk()
root.title("🔐 Secure File Encryptor/Decryptor")
root.state('zoomed')  # Fullscreen

# Variables
file_path_var = StringVar()
encrypt_password_entry = StringVar()
decrypt_password_entry = StringVar()
status_var = StringVar()

# Layout Frames
left_frame = Frame(root, bg="#007ACC", width=400)
middle_frame = Frame(root, bg="#f0f0f0", width=300)
right_frame = Frame(root, bg="#2E8B57", width=400)

left_frame.pack(side=LEFT, fill=BOTH, expand=True)
middle_frame.pack(side=LEFT, fill=Y)
right_frame.pack(side=RIGHT, fill=BOTH, expand=True)

# --- Left Panel: Decryption ---
Label(left_frame, text="🔓 Decrypt", font=("Helvetica", 20, "bold"), bg="#007ACC", fg="white").pack(pady=20)

Label(left_frame, text="Enter Password:", bg="#007ACC", fg="white").pack(pady=5)
Entry(left_frame, textvariable=decrypt_password_entry, show="*", width=30).pack(pady=5)

Button(left_frame, text="Decrypt", command=do_decrypt, bg="white", fg="#007ACC", font=("Helvetica", 12, "bold")).pack(pady=20)

# --- Middle Panel: File Selection ---
Label(middle_frame, text="📂 Choose File", font=("Helvetica", 14)).pack(pady=20)
Button(middle_frame, text="Browse", command=choose_file, font=("Helvetica", 12)).pack(pady=10)
Label(middle_frame, textvariable=file_path_var, wraplength=280, bg="#f0f0f0", fg="black").pack(padx=10, pady=10)

# --- Right Panel: Encryption ---
Label(right_frame, text="🔒 Encrypt", font=("Helvetica", 20, "bold"), bg="#2E8B57", fg="white").pack(pady=20)

Label(right_frame, text="Enter Password:", bg="#2E8B57", fg="white").pack(pady=5)
Entry(right_frame, textvariable=encrypt_password_entry, show="*", width=30).pack(pady=5)

Button(right_frame, text="Encrypt", command=do_encrypt, bg="white", fg="#2E8B57", font=("Helvetica", 12, "bold")).pack(pady=20)

# --- Status Bar ---
status_bar = Label(root, textvariable=status_var, bd=1, relief=SUNKEN, anchor=W, bg="black", fg="white", font=("Helvetica", 10))
status_bar.pack(side=BOTTOM, fill=X)

root.mainloop()
