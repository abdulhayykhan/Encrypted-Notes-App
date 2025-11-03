"""
encrypted_notes.py

Encrypted Notes App - single-file prototype

Features:
- Tkinter GUI with dark blue theme and top header (logo + title).
- Signup / Login (AAA) using PBKDF2 password hashing (stored verifier).
- Key derivation (PBKDF2) -> Fernet symmetric encryption for note contents.
- Create, View, Edit, Save, Delete notes (note management lives inside View window).
- data.json stores users (salt + pw_hash) and encrypted notes (ciphertext tokens).
- Supports optional logo.png and icon.ico placed in same directory.

Dependencies:
    pip install cryptography pillow

How to run:
    python encrypted_notes.py
"""

import os                     # To handle file and directory operations like saving and reading notes
import json                   # To store user data and encrypted notes in a structured JSON format
import base64                 # To encode and decode keys or binary data for safe storage
import hashlib                # To hash passwords securely before storing them
import datetime               # To timestamp notes or record creation/edit times
import tkinter as tk          # To create the main GUI window and interface components
from tkinter import messagebox, simpledialog, scrolledtext  # For popup dialogs, input boxes, and scrollable text areas
from tkinter import ttk       # For themed Tkinter widgets (buttons, labels, etc.)
from PIL import Image, ImageTk  # To open, resize, and display logo images in the Tkinter interface
from cryptography.hazmat.primitives import hashes  # For cryptographic hashing functions used in key derivation
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For deriving secure encryption keys from passwords
from cryptography.fernet import Fernet, InvalidToken  # For symmetric encryption/decryption and handling invalid decryption attempts


# ------------------------------
# Configuration constants
# ------------------------------
DATA_FILE = "data.json"       # persistent storage (JSON)
PBKDF2_ITERS = 200_000       # PBKDF2 iterations (class/lab-appropriate)
SALT_SIZE = 16               # bytes for per-user salt

# ------------------------------
# Storage helpers
# ------------------------------
def load_data():
    """
    Load persistent data from DATA_FILE.
    If file doesn't exist, return default structure with empty users and notes.
    """
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "notes": []}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    """Write the data back to DATA_FILE (pretty-printed)."""
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ------------------------------
# Crypto helpers
# ------------------------------
def generate_salt():
    """Return a base64-encoded random salt."""
    return base64.b64encode(os.urandom(SALT_SIZE)).decode()

def pbkdf2_hash(password: str, salt_b64: str, iters=PBKDF2_ITERS) -> str:
    """
    Derive a password verifier using PBKDF2-HMAC-SHA256.
    Returns base64-encoded digest (used only as a stored verifier, not the encryption key).
    """
    salt = base64.b64decode(salt_b64)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return base64.b64encode(dk).decode()

def derive_fernet_key(password: str, salt_b64: str, iters=PBKDF2_ITERS) -> bytes:
    """
    Derive a 32-byte key using PBKDF2 and return a base64-url-safe encoded key
    suitable for use with cryptography.fernet.Fernet.
    """
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ------------------------------
# Main application class
# ------------------------------
class EncryptedNotesApp:
    """
    The main GUI application class. All state is kept in-memory
    and persisted to data.json when changes occur.
    """
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Encrypted Notes App")   # visible in window bar
        self.root.geometry("500x460")
        self.root.resizable(False, False)

        # Try to set custom app icon if icon.ico is present.
        try:
            self.root.iconbitmap("icon.ico")
        except Exception:
            # ignore errors (file not found or unsupported platform)
            pass

        # Theme colors (dark blue)
        self.bg_dark = "#0D1B2A"      # deep navy
        self.bg_light = "#1B263B"     # panel / text bg
        self.accent = "#00BFFF"       # bright blue accents
        self.text_color = "#E0E6F0"   # light text for contrast

        # Logo image will be stored here after loading (ImageTk.PhotoImage)
        self.logo_image = None

        # Load persistent data into memory
        self.data = load_data()
        self.session = None  # session will hold {"username": ..., "fernet": Fernet(...)}

        # Configure ttk styles (buttons/labels)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton",
                        background=self.accent,
                        foreground="white",
                        font=("Segoe UI", 10, "bold"),
                        padding=6,
                        relief="flat")
        style.map("TButton", background=[("active", "#0090FF")])
        style.configure("TLabel", background=self.bg_dark, foreground=self.text_color, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=self.bg_dark, foreground=self.accent, font=("Segoe UI", 14, "bold"))

        # Configure root window background
        self.root.configure(bg=self.bg_dark)

        # Start with login screen
        self.build_login_screen()

    # ------------------------------
    # UI helpers
    # ------------------------------
    def clear_screen(self):
        """Remove all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_top_header(self, parent):
        """
        Build the top header: logo (if present) at left and "Encrypted Notes App" title at top.
        This is called on every main window so header is consistent across screens.
        """
        header_frame = tk.Frame(parent, bg=self.bg_dark)
        header_frame.pack(pady=(10, 10), anchor="w", fill="x")

        # Try to load logo.png and place it at left of header
        try:
            img = Image.open("logo.png")
            img = img.resize((60, 60))
            self.logo_image = ImageTk.PhotoImage(img)
            tk.Label(header_frame, image=self.logo_image, bg=self.bg_dark).pack(side="top", padx=(10, 12))
        except Exception:
            # If logo not available or PIL error, skip without crashing
            pass

        # App title (large)
        tk.Label(header_frame,
                 text="Encrypted Notes App",
                 bg=self.bg_dark,
                 fg=self.accent,
                 font=("Segoe UI", 16, "bold")).pack(side="top", padx=(0, 10))

    # ------------------------------
    # Authentication screens
    # ------------------------------
    def build_login_screen(self):
        """
        Build the login / signup screen. Logo + title at top, then username/password fields.
        """
        self.clear_screen()
        self.build_top_header(self.root)

        frame = ttk.Frame(self.root, padding=18)
        frame.pack(expand=True)

        ttk.Label(frame, text="Username").pack(pady=6)
        self.username_entry = ttk.Entry(frame, width=32)
        self.username_entry.pack()

        ttk.Label(frame, text="Password").pack(pady=6)
        self.password_entry = ttk.Entry(frame, show="*", width=32)
        self.password_entry.pack()

        ttk.Button(frame, text="Login", command=self.login).pack(pady=12)
        ttk.Button(frame, text="Sign Up", command=self.signup).pack()
        ttk.Button(frame, text="Quit", command=self.root.destroy).pack(pady=10)

    def build_main_screen(self):
        """
        Build the main menu screen after successful login.
        The header is shown at top (logo + title) and welcome text below it.
        Note: delete was removed from main menu per requirements.
        """
        self.clear_screen()
        self.build_top_header(self.root)

        container = ttk.Frame(self.root, padding=18)
        container.pack(expand=True)

        ttk.Label(container, text=f"Welcome, {self.session['username']}!",
                  foreground=self.accent, font=("Segoe UI", 11, "bold")).pack(pady=6)

        ttk.Button(container, text="📝 Create Note", width=26, command=self.create_note).pack(pady=6)
        ttk.Button(container, text="📂 View Notes", width=26, command=self.view_notes).pack(pady=6)
        ttk.Button(container, text="🔑 Change Password", width=26, command=self.change_password).pack(pady=6)
        ttk.Button(container, text="🚪 Logout", width=26, command=self.logout).pack(pady=10)

    # ------------------------------
    # Auth logic (signup/login)
    # ------------------------------
    def signup(self):
        """Create a new user with per-user salt and stored password verifier (pbkdf2_hash)."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning("Error", "Username and password required.")
            return
        if username in self.data["users"]:
            messagebox.showwarning("Error", "Username already exists.")
            return
        salt_b64 = generate_salt()
        pw_hash = pbkdf2_hash(password, salt_b64)
        # store salt and verifier; we never store raw passwords
        self.data["users"][username] = {"salt": salt_b64, "pw_hash": pw_hash}
        save_data(self.data)
        messagebox.showinfo("Success", "Account created successfully! Please log in.")

    def login(self):
        """
        Verify username & password using stored verifier (pbkdf2_hash).
        On success, derive Fernet key and enter session.
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username not in self.data["users"]:
            messagebox.showerror("Error", "No such user.")
            return
        salt_b64 = self.data["users"][username]["salt"]
        expected_hash = self.data["users"][username]["pw_hash"]
        if pbkdf2_hash(password, salt_b64) != expected_hash:
            messagebox.showerror("Error", "Incorrect password.")
            return
        # create Fernet instance for session encryption/decryption
        key = derive_fernet_key(password, salt_b64)
        self.session = {"username": username, "fernet": Fernet(key)}
        self.build_main_screen()

    # ------------------------------
    # Notes - create / view / edit / delete
    # ------------------------------
    def create_note(self):
        """
        Open a Create Note window (top header shown by default on main root).
        The window includes a scrolled text area and Save button. Note content is encrypted.
        """
        title = simpledialog.askstring("New Note", "Enter note title:")
        if not title:
            return

        win = tk.Toplevel(self.root)
        win.title("Encrypted Notes App - Create Note")
        # try set icon for popup window too
        try:
            win.iconbitmap("icon.ico")
        except Exception:
            pass
        win.geometry("520x400")
        win.configure(bg=self.bg_dark)

        # text area style (dark background)
        text = scrolledtext.ScrolledText(win, width=60, height=17, wrap=tk.WORD,
                                        font=("Consolas", 10), bg=self.bg_light,
                                        fg=self.text_color, insertbackground=self.accent)
        text.pack(padx=10, pady=10)

        def save_it():
            content = text.get("1.0", tk.END).strip()
            if not content:
                messagebox.showwarning("Empty", "Note is empty.")
                return
            # encrypt with session fernet
            token = self.session["fernet"].encrypt(content.encode()).decode()
            note = {
                "owner": self.session["username"],
                "title": title,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "ciphertext": token
            }
            self.data["notes"].append(note)
            save_data(self.data)
            messagebox.showinfo("Saved", "Note encrypted and saved.")
            win.destroy()

        ttk.Button(win, text="Save Note", command=save_it).pack(pady=10)

    def view_notes(self):
        """
        Open a View Notes window. This window contains:
          - top header (logo + title)
          - listbox (user's notes)
          - scrolled text area for reading/editing
          - Save Changes and Delete Note buttons (delete here, not in main menu)
        """
        user_notes = [n for n in self.data["notes"] if n["owner"] == self.session["username"]]
        if not user_notes:
            messagebox.showinfo("Info", "No notes found.")
            return

        win = tk.Toplevel(self.root)
        win.title("Encrypted Notes App - View Notes")
        try:
            win.iconbitmap("icon.ico")
        except Exception:
            pass
        win.geometry("650x650")
        win.configure(bg=self.bg_dark)

        # header with logo + title at top of this window
        self.build_top_header(win)

        tk.Label(win, text="Select a note to view/edit:", bg=self.bg_dark,
                 fg=self.accent, font=("Segoe UI", 11, "bold")).pack(pady=5)

        listbox = tk.Listbox(win, width=60, height=8, bg=self.bg_light,
                             fg=self.text_color, selectbackground=self.accent, font=("Consolas", 10))
        for n in user_notes:
            listbox.insert(tk.END, f"{n['title']}  ({n['created_at'][:19]})")
        listbox.pack(padx=10, pady=5)

        # text area for plaintext display/edit
        text = scrolledtext.ScrolledText(win, width=70, height=15, wrap=tk.WORD,
                                        font=("Consolas", 10), bg=self.bg_light,
                                        fg=self.text_color, insertbackground=self.accent)
        text.pack(padx=10, pady=5)

        selected_note = {"index": None}  # store current selected index (mutable closure)

        def show_selected(_evt=None):
            """When a listbox item is selected, decrypt and show its plaintext."""
            idx = listbox.curselection()
            if not idx:
                return
            selected_note["index"] = idx[0]
            note = user_notes[idx[0]]
            try:
                plaintext = self.session["fernet"].decrypt(note["ciphertext"].encode()).decode()
            except InvalidToken:
                plaintext = "[Error decrypting note — wrong key or corrupted data]"
            text.delete("1.0", tk.END)
            text.insert(tk.END, plaintext)

        def save_note():
            """Encrypt edited text and save back to data store for the selected note."""
            if selected_note["index"] is None:
                messagebox.showwarning("Warning", "Select a note first.")
                return
            new_text = text.get("1.0", tk.END).strip()
            enc = self.session["fernet"].encrypt(new_text.encode()).decode()
            # update the in-memory user_notes list (and underlying self.data on save)
            user_notes[selected_note["index"]]["ciphertext"] = enc
            save_data(self.data)
            messagebox.showinfo("Saved", "Note updated successfully!")

        def delete_note():
            """Delete the currently selected note after confirmation."""
            if selected_note["index"] is None:
                messagebox.showwarning("Warning", "Select a note first.")
                return
            note = user_notes[selected_note["index"]]
            confirm = messagebox.askyesno("Delete", f"Delete note '{note['title']}'?")
            if confirm:
                # remove from global data list (self.data["notes"])
                self.data["notes"].remove(note)
                save_data(self.data)
                # update UI
                listbox.delete(selected_note["index"])
                text.delete("1.0", tk.END)
                selected_note["index"] = None
                messagebox.showinfo("Deleted", "Note deleted successfully.")

        # Bind selection event to show_selected
        listbox.bind("<<ListboxSelect>>", show_selected)

        # Save and Delete buttons inside the view window
        ttk.Button(win, text="💾 Save Changes", command=save_note).pack(pady=6)
        ttk.Button(win, text="🗑️ Delete Note", command=delete_note).pack(pady=2)

    # ------------------------------
    # Change password / logout
    # ------------------------------
    def change_password(self):
        """
        Change the logged-in user's password:
         - verify current password
         - derive new key (new salt)
         - decrypt all user's notes with old key and re-encrypt with new key
         - update stored salt + pw_hash
        """
        old_pw = simpledialog.askstring("Change Password", "Enter current password:", show="*")
        username = self.session["username"]
        salt_b64 = self.data["users"][username]["salt"]
        if pbkdf2_hash(old_pw, salt_b64) != self.data["users"][username]["pw_hash"]:
            messagebox.showerror("Error", "Incorrect current password.")
            return
        new_pw = simpledialog.askstring("Change Password", "Enter new password:", show="*")
        if not new_pw:
            return

        # prepare new salt / verifier & new Fernet
        new_salt = generate_salt()
        new_pw_hash = pbkdf2_hash(new_pw, new_salt)
        old_fernet = self.session["fernet"]
        new_key = derive_fernet_key(new_pw, new_salt)
        new_fernet = Fernet(new_key)

        # re-encrypt all notes owned by user
        for n in self.data["notes"]:
            if n["owner"] == username:
                plaintext = old_fernet.decrypt(n["ciphertext"].encode())
                n["ciphertext"] = new_fernet.encrypt(plaintext).decode()

        # update stored credentials & persist
        self.data["users"][username]["salt"] = new_salt
        self.data["users"][username]["pw_hash"] = new_pw_hash
        save_data(self.data)
        messagebox.showinfo("Done", "Password changed & notes re-encrypted. Please log in again.")
        # force logout to refresh session
        self.session = None
        self.build_login_screen()

    def logout(self):
        """End session and return to login screen."""
        self.session = None
        self.build_login_screen()

# ------------------------------
# Run the application
# ------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedNotesApp(root)
    root.mainloop()
