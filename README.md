# Chrome App-Bound Decryption

Advanced Chrome credential decryption tool that supports all encryption versions (DPAPI, v10, v11, v20) including the latest App-Bound encryption with CNG key derivation and LSASS impersonation.

---

### ⚙️ How It Works

- **Multi-Version Support**: Handles DPAPI, v10, v11, and v20 encryption schemes automatically.
- **App-Bound Decryption**: Bypasses Chrome's latest v20 App-Bound encryption using CNG API and LSASS token impersonation.
- **Master Key Derivation**: Extracts and decrypts the master key from Chrome's Local State file using multiple cryptographic layers.
- **Token Impersonation**: Uses SeDebugPrivilege to impersonate LSASS process for system-level decryption.
- **Universal Decryption**: Automatically detects encryption version and applies appropriate decryption method.
- **Multi-Profile Support**: Processes all Chrome profiles (Default, Profile 1, Profile 2, etc.).
- **Comprehensive Data Extraction**: Retrieves passwords, cookies, and autofill data from Chrome databases.

---

## 📁 Setup

### 1. Requirements

Install required libraries using pip:
```python
pip install PythonForWindows pycryptodome
```

### 2. System Requirements

- **Administrator Privileges**: Required for LSASS impersonation and SeDebugPrivilege
- **Windows OS**: Uses Windows-specific CNG and DPAPI APIs
- **Chrome Installation**: Target Chrome browser must be installed

---

### 🚀 Usage

Run the script with administrator privileges:
```bash
python main.py
```

#### 📂 Output Structure
```
chrome/
├── default/
│   ├── passwords.txt
│   ├── cookies.txt
│   └── auto_fills.txt
├── profile 1/
│   ├── passwords.txt
│   ├── cookies.txt
│   └── auto_fills.txt
└── ...
```

---

### 🔐 Encryption Support

- **DPAPI**: Legacy Windows Data Protection API encryption
- **v10/v11**: Chrome's intermediate encryption versions with DPAPI
- **v20**: Latest App-Bound encryption with:
  - AES-256-GCM with hardcoded key (Flag 1)
  - ChaCha20-Poly1305 with hardcoded key (Flag 2)
  - AES-256-GCM with CNG-encrypted key + XOR obfuscation (Flag 3)

---

### 🛠️ Technical Features

- **CNG Integration**: Uses Microsoft's Cryptography Next Generation API for hardware-bound key decryption
- **LSASS Token Duplication**: Creates impersonation token from Local Security Authority Subsystem Service
- **SQLite Database Handling**: Safely copies and processes Chrome's locked database files
- **Blob Parsing**: Custom parser for Chrome's encrypted key blob structure
- **Multi-Cipher Support**: AES-GCM, ChaCha20-Poly1305, and hybrid encryption schemes

---

### 📊 Supported Data Types

- **🔑 Passwords**: Login credentials from all websites
- **🍪 Cookies**: Session cookies with proper Netscape format
- **📝 Autofill**: Form data and personal information
- **👤 Multi-Profile**: All Chrome user profiles automatically detected

---

### :rose: Special Thanks

[@runassu](https://github.com/runassu) I added and improved several features to the [project](https://github.com/runassu/chrome_v20_decryption).

---

### ⚠️ Disclaimer

This project has been developed for educational and security research purposes only. Unauthorized access to any system or data is illegal and strictly prohibited. The developer is not responsible for any misuse of this tool. Only use on systems you own or have explicit permission to test.
