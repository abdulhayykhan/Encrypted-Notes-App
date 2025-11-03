# 🔐 Encrypted Notes App

A Python-based desktop application that allows users to **securely create, view, edit, and manage personal notes** with encryption and password-protected access.  
This project integrates **cryptography**, **authentication (AAA Framework)**, and a modern **Tkinter GUI** — developed as part of the course **Information Security** in the **3rd semester of BS Artificial Intelligence** at **Dawood University of Engineering & Technology (DUET)**.

---

## 📖 Overview

The **Encrypted Notes App** demonstrates how **core information security principles** — such as *confidentiality, integrity,* and *access control* — can be practically implemented in a real-world scenario.  
It allows users to store sensitive notes securely, ensuring that even if the storage file is accessed externally, the data remains encrypted and unreadable.

---

## 🧠 Features

- **User Authentication (AAA Framework)**  
  Secure login system with password hashing and access control.

- **Symmetric Encryption (Fernet)**  
  Each note is encrypted before saving and decrypted only upon access.

- **Interactive GUI (Tkinter)**  
  - Blue-themed modern design  
  - Custom logo and clean navigation  
  - Create, view, edit, and delete note options

- **Local Encrypted Storage**  
  Notes are stored in a local JSON file as encrypted data.

---

## 🧩 Technologies Used

| Component | Purpose |
|------------|----------|
| `Python` | Core programming language |
| `Tkinter` | Graphical user interface |
| `cryptography` | Symmetric encryption (Fernet) |
| `hashlib` | Password hashing |
| `json` | Local encrypted data storage |
| `PIL (Pillow)` | Logo image handling |

---

## 🧱 Project Structure

```
Encrypted-Notes-App/
│
├── encrypted_notes.py # Main source code (single file)
├── logo.png # App logo displayed in GUI
├── data.json # Encrypted notes storage file
└── README.md # Project documentation
```

---

## ⚙️ Installation & Setup

### 1️⃣ Prerequisites
Ensure **Python 3.8+** is installed.

### 2️⃣ Install Dependencies
Run the following command:
```bash
pip install cryptography pillow
```

### 3️⃣ Run the Application
Execute the app:
```bash
python encrypted_notes.py
```

--- 

## 🚀 Usage Guide

1. Launch the app to open the Login Window.
2. Enter a username and password.
  - If new, an account is automatically created.
3. After login:
  - Click Create Note → Add a new encrypted note.
  - Click View Notes → View, edit, or delete saved notes.
4. All notes are encrypted and stored in `data.json`.

---

## 🔐 Security Concepts Integrated

| Concept |	Description |
| - | - |
| Cryptography (Fernet) |	Encrypts and decrypts note content |
| AAA Framework	| Ensures authentication and access control |
| Hashing |	Protects stored passwords |
| Access Control |	Restricts unauthorized access |
| Data Integrity |	Maintains consistency and reliability of data |

---

## 👨‍💻 Author

[**Abdul Hayy Khan**](https://www.linkedin.com/in/abdul-hayy-khan/) 

📫 abdulhayykhan.1@gmail.com

---

## 📌 License

This project is open-source and available for educational use under the **MIT License**.
