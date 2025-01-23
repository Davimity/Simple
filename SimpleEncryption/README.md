# SimpleEncryption

**SimpleEncryption** is a modular library for cryptographic operations, designed to make encryption, hashing, and key derivation simple, flexible, and efficient.

---

## ✨ Features
- **🔒 Encryption**:
  - AES (256-bit) with configurable cipher modes and padding.
  - ChaCha20-Poly1305 for authenticated encryption.
- **🔑 Hashing**:
  - Secure hashing algorithms: SHA-256 and SHA-512.
- **🧩 Key Derivation**:
  - Argon2i, Argon2d, and Argon2id for advanced password hashing.
  - PBKDF2-based key derivation as a fallback.
- **⚙️ Salt and Nonce Generation**:
  - Generate secure salts and nonces dynamically.
- **💡 Thread-safe and configurable**.

---

## 📦 Installation

Install **SimpleEncryption** via NuGet:

```bash
dotnet add package SimpleEncryption
```

---

## 📚 Overview

### 🔒 **AES Encryption**
Encrypt and decrypt strings and byte arrays using AES (256-bit):
```csharp
using SimpleEncryption.Encryption;

byte[] key = Aes.GenerateKey("password", "salt");
byte[] iv = Aes.GenerateIv("password", "salt");

string encrypted = Aes.Encrypt("Hello, World!", key, iv);
string decrypted = Aes.Decrypt(encrypted, key, iv);

Console.WriteLine($"Decrypted: {decrypted}");
```

### ⚡ **ChaCha20-Poly1305 Encryption**
Lightweight and secure encryption with associated data (AAD):
```csharp
using SimpleEncryption.Encryption;

byte[] key = ChaCha20.GenerateKey("password", "salt");
byte[] nonce = ChaCha20.GenerateNonce();

string encrypted = ChaCha20.Encrypt("Hello, World!", key, nonce);
string decrypted = ChaCha20.Decrypt(encrypted, key);

Console.WriteLine($"Decrypted: {decrypted}");
```

### 🔑 **Hashing (SHA-256 and SHA-512)**
Hash strings securely with or without salt:
```csharp
using SimpleEncryption.Hashing;

string sha256Hash = Sha256.Hash("password");
string sha512Hash = Sha512.Hash("password");

Console.WriteLine($"SHA-256 Hash: {sha256Hash}");
Console.WriteLine($"SHA-512 Hash: {sha512Hash}");
```

### 🧩 **Argon2 Key Derivation**
Derive secure keys with Argon2 (i, d, id):
```csharp
using SimpleEncryption.Derivation.Argon2;

string argon2Key = Argon2i.DeriveKey("password", "salt", keyLength: 32);
Console.WriteLine($"Argon2i Derived Key: {argon2Key}");
```

---

## 🤝 Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request on [GitHub](https://github.com/your-repo-url).

---

## 📜 License
This project is licensed under the **MIT License**.
