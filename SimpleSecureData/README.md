# 🔒 SimpleSecureData

**SimpleSecureData** is a cross-platform library designed to enhance security by ensuring sensitive data remains encrypted in memory at all times. It leverages platform-specific secure storage mechanisms for optimal security and falls back to a custom AES-based encryption for unsupported platforms.

---

## 📖 Table of Contents
1. [🚀 Features](#-features)
2. [💾 Platform-Specific Implementations](#-platform-specific-implementations)
3. [📦 Installation](#-installation)
4. [📚 Usage Examples](#-usage-examples)
   - [SecureBytes](#securebytes)
   - [SecureString](#securestring)
   - [Platform-Secure Storage](#platform-secure-storage)
5. [🤝 Contributing](#-contributing)
6. [📜 License](#-license)

---

## 🚀 Features

- **Memory Encryption**: All sensitive data is encrypted in memory using ChaCha20.
- **Platform-Specific Secure Storage**:
  - **Windows**: DPAPI for secure local storage.
  - **Android**: AndroidX **EncryptedSharedPreferences**.
  - **iOS**: **Keychain Services**.
- **Secure Data Types**:
  - `SecureBytes`: Securely manage byte arrays.
  - `SecureString`: A secure implementation for strings.
  - `SecureChar`: Handle individual characters securely.
- **Cross-Platform Support**: Supports Windows, Android, iOS, macOS, Linux, and more.
- **Fallback Mechanism**: AES-based encryption with HMAC for platforms without secure storage APIs.
- **Flexible APIs**:
  - Serialize, deserialize, append, and split secure objects.
  - Automatic memory cleanup with `CryptographicOperations.ZeroMemory`.

---

## 💾 Platform-Specific Implementations

| **Platform** | **Implementation**                                                                 |
|--------------|-------------------------------------------------------------------------------------|
| **Windows**  | DPAPI (`System.Security.Cryptography.ProtectedData`).                              |
| **Android**  | AndroidX **EncryptedSharedPreferences** with AES-256-GCM.                         |
| **iOS**      | **Keychain Services** for secure storage.                                          |
| **Others**   | AES-256 encryption with HMAC for integrity verification (fallback).                |

---

## 📦 Installation

1. Add the package to your project:
   ```bash
   dotnet add package SimpleSecureData
   ```

2. Import the necessary namespaces:
   ```csharp
   using SimpleSecureData;
   using SimpleSecureData.Text;
   ```

---

## 📚 Usage Examples

### **SecureBytes**
Securely store and manipulate byte arrays:
```csharp
var secureBytes = new SecureBytes(new byte[] { 1, 2, 3, 4 });
secureBytes.AppendData(new byte[] { 5, 6, 7 });
byte[] plainBytes = secureBytes.GetBytes(); // Decrypt to access data
secureBytes.Dispose(); // Clean up memory
```

---

### **SecureString**
Handle strings securely in memory:
```csharp
var secureString = new SecureString("SensitiveData");
secureString.AppendData(" MoreData");

// Retrieve as plain text (temporarily)
string plainText = secureString.ToString();

secureString.Dispose(); // Clean up memory
```

---

### **Platform-Secure Storage**
Store and retrieve secrets using platform-specific secure storage:
```csharp
byte[] sensitiveData = Encoding.UTF8.GetBytes("Sensitive Data");

// Store data securely
Guid secretId = PlatformSecureStorage.StoreSecret(sensitiveData);

// Retrieve data securely
byte[] retrievedData = PlatformSecureStorage.RetrieveSecret(secretId);

// Remove secret
PlatformSecureStorage.RemoveSecret(secretId);
```

---

## 🔧 Technical Notes
- **Windows (DPAPI)**:
  - Data is encrypted with `ProtectedData` using `DataProtectionScope.CurrentUser`.
- **Android**:
  - Uses AndroidX `EncryptedSharedPreferences` with AES-256-GCM and HMAC.
- **iOS**:
  - Integrates with the **Keychain** to securely store and retrieve data.
- **Fallback Mechanism**:
  - AES-256 with HMAC for encryption and integrity verification.
- **ChaCha20 Encryption**:
  - Used for in-memory encryption with optional Associated Data (AAD).

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request on [GitHub](https://github.com/YourRepo/SimpleSecureData).

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
