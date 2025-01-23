# 🚀 SimpleCryptography

A **powerful and modular library** for cryptographic operations, including encryption, hashing, and key derivation. SimpleCryptography provides easy-to-use, efficient, and flexible methods to integrate cryptography into your projects.

---

## 📖 **Table of Contents**
1. [✨ Features](#-features)
2. [📦 Installation](#-installation)
3. [📚 Modules Overview](#-modules-overview)
   - [🔒 AES Encryption](#-aes-encryption)
   - [⚡ ChaCha20-Poly1305 Encryption](#-chacha20-poly1305-encryption)
   - [🔑 Hashing (SHA-256 and SHA-512)](#-hashing)
   - [🧩 Argon2 Key Derivation](#-argon2-key-derivation)
4. [📋 Usage Examples](#-usage-examples)
5. [🤝 Contributing](#-contributing)
6. [📜 License](#-license)

---

## ✨ **Features**

- **🔒 Encryption**:
  - AES with configurable cipher modes and padding.
  - ChaCha20-Poly1305 for lightweight and secure encryption.
- **🔑 Hashing**:
  - Secure hashing algorithms: SHA-256 and SHA-512.
- **🧩 Key Derivation**:
  - Argon2i, Argon2d, and Argon2id for advanced password hashing and key derivation.
  - PBKDF2-based key derivation as a fallback.
- **⚙️ Salt and Nonce Generation**:
  - Generate secure salts and nonces with configurable sizes.
- **💡 Flexibility**:
  - Thread-safe encryption and key derivation.
  - Configurable parameters for memory, iterations, and thread usage.

---

## 📦 **Installation**

Install SimpleCryptography via NuGet:
```bash
Install-Package SimpleCryptography
```

Or use the .NET CLI:
```bash
dotnet add package SimpleCryptography
```

---

## 📚 **Modules Overview**

### 🔒 **AES Encryption**
- Symmetric encryption algorithm supporting 256-bit keys and initialization vectors (IVs).
- Fully customizable cipher modes and padding.

#### Features:
- **Encrypt/Decrypt Strings and Byte Arrays**
- **Generate Keys and IVs** dynamically.

---

### ⚡ **ChaCha20-Poly1305 Encryption**
- Modern and efficient authenticated encryption algorithm.
- Requires 256-bit keys and 96-bit (12-byte) nonces.

#### Features:
- **Associated Data (AAD)** support for additional authentication.
- **Generate Keys and Nonces** dynamically.

---

### 🔑 **Hashing**
- Provides implementations of **SHA-256** and **SHA-512** for secure hashing.

#### Features:
- Supports hashing with or without salt.
- Secure memory clearing for sensitive data.

---

### 🧩 **Argon2 Key Derivation**
- Advanced key derivation algorithms (Argon2i, Argon2d, Argon2id).
- Configurable parameters for memory usage, iterations, and parallelism.
- Using Konscious.Security.Cryptography.Argon2 implementation.

#### Features:
- **Derive Keys** with flexible configurations.
- **Generate Salts** dynamically using SHA-512.

---

## 📋 **Usage Examples**

### 🔒 **AES Encryption**
```csharp
using SimpleCryptography.Encryption;

byte[] key = Aes.GenerateKey("password", "salt");
byte[] iv = Aes.GenerateIv("password", "salt");

string encrypted = Aes.Encrypt("Hello, World!", key, iv);
string decrypted = Aes.Decrypt(encrypted, key, iv);

Console.WriteLine($"Decrypted: {decrypted}");
```

---

### ⚡ **ChaCha20-Poly1305 Encryption**
```csharp
using SimpleCryptography.Encryption;

byte[] key = ChaCha20.GenerateKey("password", "salt");
byte[] nonce = ChaCha20.GenerateNonce();

string encrypted = ChaCha20.Encrypt("Hello, World!", key, nonce);
string decrypted = ChaCha20.Decrypt(encrypted, key);

Console.WriteLine($"Decrypted: {decrypted}");
```

---

### 🔑 **Hashing**
#### SHA-256:
```csharp
using SimpleCryptography.Hashing;

string hash = Sha256.Hash("password");
Console.WriteLine($"SHA-256 Hash: {hash}");
```

#### SHA-512:
```csharp
using SimpleCryptography.Hashing;

string hash = Sha512.Hash("password");
Console.WriteLine($"SHA-512 Hash: {hash}");
```

---

### 🧩 **Argon2 Key Derivation**
#### Argon2i:
```csharp
using SimpleCryptography.Derivation.Argon2;

string key = Argon2i.DeriveKey("password", "salt", keyLength: 32);
Console.WriteLine($"Argon2i Derived Key: {key}");
```

#### Argon2d:
```csharp
using SimpleCryptography.Derivation.Argon2;

string key = Argon2d.DeriveKey("password", "salt", keyLength: 32);
Console.WriteLine($"Argon2d Derived Key: {key}");
```

#### Argon2id:
```csharp
using SimpleCryptography.Derivation.Argon2;

string key = Argon2id.DeriveKey("password", "salt", keyLength: 32);
Console.WriteLine($"Argon2id Derived Key: {key}");
```

---

## 🤝 **Contributing**

Contributions are welcome! If you have ideas for improvements or find issues, feel free to create a pull request or open an issue on GitHub.

---

## 📜 **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
