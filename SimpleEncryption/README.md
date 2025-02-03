# SimpleEncryption

**SimpleEncryption** is a modular library for cryptographic operations, designed to make encryption, hashing, and key derivation simple, flexible, and efficient.

---

## ✨ Features
- **🔒 Encryption**:
  - AES (256-bit) with configurable cipher modes and padding.
  - ChaCha20-Poly1305 for authenticated encryption.
- **🔑 Hashing**:
  - Secure hashing algorithms: SHA-256 and SHA-512.
- **🧬 Key Derivation**:
  - PBKDF2 key derivation.
- **⚙️ Salt and Nonce Generation**:
  - Generate secure salts and nonces dynamically.
- **💡 Thread-safe and configurable**.
- **⚠️ OS Compatibility Notes**:
  - `ChaCha20` is **not supported** on `iOS`, `tvOS`, and `browser environments`.
  - `AES` is **not supported** on `browser environments`.

---

## 📚 Installation

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

// Encrypt a string
string encrypted = Aes.Encrypt("Hello, World!", key, iv);
string decrypted = Aes.Decrypt(encrypted, key, iv);

// Encrypt a byte array
byte[] encryptedBytes = Aes.Encrypt(Encoding.UTF8.GetBytes("Hello, World!"), key, iv);
byte[] decryptedBytes = Aes.Decrypt(encryptedBytes, key, iv);

Console.WriteLine($"Decrypted: {decrypted}");
```

### ⚡ **ChaCha20-Poly1305 Encryption**
Lightweight and secure encryption with associated data (AAD):
```csharp
using SimpleEncryption.Encryption;

byte[] key = ChaCha20.GenerateKey("password", "salt");
byte[] nonce = ChaCha20.GenerateNonce();

// Encrypt a string
string encrypted = ChaCha20.Encrypt("Hello, World!", key, nonce);
string decrypted = ChaCha20.Decrypt(encrypted, key, nonce);

// Encrypt a byte array
byte[] encryptedBytes = ChaCha20.Encrypt(Encoding.UTF8.GetBytes("Hello, World!"), key, nonce);
byte[] decryptedBytes = ChaCha20.Decrypt(encryptedBytes, key, nonce);

Console.WriteLine($"Decrypted: {decrypted}");
```

### 🔑 **Hashing (SHA-256 and SHA-512)**
Hash strings securely with or without salt:
```csharp
using SimpleEncryption.Hashing;

// Hash a string
string sha256Hash = Sha256.Hash("password");
string sha512Hash = Sha512.Hash("password");

// Hash a string with salt
string sha256Salted = Sha256.Hash("password", "salt");
string sha512Salted = Sha512.Hash("password", "salt");

Console.WriteLine($"SHA-256 Hash: {sha256Hash}");
Console.WriteLine($"SHA-512 Hash: {sha512Hash}");
```

### 🧬 **PBKDF2 Key Derivation**
Derive secure keys:
```csharp
using SimpleEncryption.Derivation;

byte[] salt = Encoding.UTF8.GetBytes("random_salt");

// Derive a key from a password
string derivedKey = Pbkdf2.DeriveKey("password", salt);
byte[] derivedKeyBytes = Pbkdf2.DeriveKey(Encoding.UTF8.GetBytes("password"), salt);

Console.WriteLine($"Derived Key: {derivedKey}");
```

---

## 🤝 Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request on [GitHub](https://github.com/Davimity/Simple/tree/main/SimpleEncryption).

---

## 🐝 OS Compatibility
- **ChaCha20-Poly1305** is **not supported** on:
  - `iOS`
  - `tvOS`
  - `browser environments`
- **AES Encryption** is **not supported** on:
  - `browser environments`

---

## 🐝 License
This project is licensed under the **MIT License**.

## ⚠️ Security & Disclaimer

This library has been developed with the goal of providing the highest possible security in encryption, hashing, and key derivation algorithms. However:

- There is **no guarantee** that the implementation is completely free of vulnerabilities.
- **Use this library at your own risk**.
- No warranty is provided regarding its suitability for critical security applications or highly sensitive environments.

If you intend to use this library in a security-sensitive environment, it is **strongly recommended** to conduct additional security audits and follow best cryptographic practices.
