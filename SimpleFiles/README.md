# 🛠️ SimpleFiles Library

The **SimpleFiles Library** is a powerful and easy-to-use solution for handling file and folder operations in .NET. With built-in encryption and flexibility, it simplifies file management while keeping your data secure. 🔒

---

## 🚀 Features

### File Management 📄
- **Read and Write Operations**: Handle file content seamlessly.
- **Encryption Support**: Secure files with AES or ChaCha20 encryption.
- **Customizable Options**: Append, overwrite, or create files as needed.
- **Re-encrypt Files**: Update encryption keys or parameters on existing files.
- **Rename, Delete, and Check Existence**: Perform essential file operations effortlessly.

### Folder Management 📁
- **Create, Delete, Rename**: Manage folder structure programmatically.
- **Recursive Operations**: Copy or move entire folder trees.
- **Get Folder Content**: Retrieve files or subfolders with flexible filtering.
- **Check and Empty Folders**: Validate and clean up folder contents.

### Security 🛡️
- **Memory Safety**: Sensitive data like keys and decrypted content are cleared after use.
- **Support for Secure Algorithms**: Choose between AES and ChaCha20 for encryption.

---

## 📚 Installation

Install the library via NuGet:

```bash
dotnet add package SimpleFiles
```

---

## 📝 Usage

Reading a File
```csharp
var content = File.Read("example.txt", decrypt: true, key: myKey, ivOrNonce: myIv, encryptionAlgorithm: EncryptionAlgorithm.Aes);
```

Writing to a File
```csharp
File.Write("example.txt", new[] { "Line 1", "Line 2" }, encrypt: true, key: myKey, encryptionAlgorithm: EncryptionAlgorithm.ChaCha20);
```

Creating and Deleting a Folder
```csharp
Folder.Create("myFolder");
Folder.Delete("myFolder", deleteRecursive: true);
```

---

## 📌 Why Choose SimpleFiles?

- **Focus on Security**: Encryption support ensures your data stays safe.
- **Ease of Use**: Simple APIs make file and folder operations intuitive.
- **Extensibility**: Built with flexibility for a variety of use cases.
- **Performance**: Efficient handling of large files and folders.


---

## 📦 Contributions

Contributions are welcome! Feel free to submit issues or pull requests.

---

## 🏷️ License

This project is licensed under the MIT License.