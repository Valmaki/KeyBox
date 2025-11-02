# 🔐 KeysHandler

**KeysHandler** is a lightweight Java console program for creating, editing, and viewing cryptographic key files.  
It supports both **asymmetric** (e.g., RSA, EC) and **symmetric** (e.g., AES) algorithms and stores them in a compact, custom binary format.

---

## ✨ Features

- 🧩 Supports **RSA**, **EC**, and **AES** algorithms  
- 📦 Stores multiple keys (public, private, secret) in one file  
- 🪶 Simple, compact file structure  
- 🔁 Allows adding, removing, and saving keys interactively  
- 📖 Reads and reconstructs keys directly from disk  
- ⚙️ Fully self-contained — no external dependencies beyond the Java standard library

---

## 🚀 How to Run

This version of KeysHandler comes **pre-compiled**.  
To run it, simply execute the provided `.class` file with the Java Runtime:

```bash
java KeysHandler
```

> 🟡 Note: The program is interactive. It will ask for input such as algorithm name, key size, and file paths.




---

🧠 Available operations

Command	Description

c	- Create a new key file
e	- Edit an existing key file
p	- Print one of the stored keys
l	- Exit the program



---

🧩 Example

Creating an RSA key pair:
```
Set operation! (c-create/e-edit/p-print/l-exit) c
Algorithm name: RSA
The key size: 2048
Save to: rsa.keys
```

Output:
```
The RSA keypair saved to "rsa.keys".
```
Printing a public key:

```
Set operation! (c-create/e-edit/p-print/l-exit) p
Path to the keys file: rsa.keys
Key to print (pub-public key/priv-private key/s-secret): pub
```

---

📘 File structure overview

Each .keys file begins with:

1. A single header byte describing which keys exist (bitmask)


2. 0–3 offsets (integers) showing where each key is stored


3. The algorithm name in UTF-8


4. The encoded key data blocks



This structure is designed to be compact, fast to parse, and easily extendable in the future.


---

🧱 Project status

This is the translated version of the program.
It is not yet designed for integration into other systems and has no JAR build at this stage.
A future release will include packaging, library functions, and CLI argument support.


---

⚖️ License

This project is intended to be released under the MIT License,
allowing anyone to freely use, modify, and distribute it.


---

👤 Author

Máté — independent developer interested in software development, security, and encryption systems.
Feedback and improvement ideas are always welcome!
