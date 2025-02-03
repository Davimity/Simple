# SimpleEncryption

**SimpleEncryption** es una biblioteca modular para operaciones criptográficas, diseñada para hacer que el cifrado, hashing y derivación de claves sean simples, flexibles y eficientes.

---

## ✨ Características
- **🔒 Cifrado**:
  - AES (256 bits) con modos de cifrado y padding configurables.
  - ChaCha20-Poly1305 para cifrado autenticado.
- **🔑 Hashing**:
  - Algoritmos de hashing seguros: SHA-256 y SHA-512.
- **🧬 Derivación de Claves**:
  - Derivación de claves con PBKDF2.
- **⚙️ Generación de Salt y Nonce**:
  - Genera salts y nonces seguros dinámicamente.
- **💡 Seguro para múltiples hilos y configurable**.
- **⚠️ Notas de compatibilidad con SO**:
  - `ChaCha20` **no es compatible** con `iOS`, `tvOS` y `entornos de navegador`.
  - `AES` **no es compatible** con `entornos de navegador`.

---

## 📚 Instalación

Instala **SimpleEncryption** a través de NuGet:

```bash
dotnet add package SimpleEncryption
```

---

## 📚 Descripción general

### 🔒 **Cifrado AES**
Cifra y descifra cadenas y arreglos de bytes usando AES (256 bits):
```csharp
using SimpleEncryption.Encryption;

byte[] key = Aes.GenerateKey("password", "salt");
byte[] iv = Aes.GenerateIv("password", "salt");

// Cifrar una cadena
string encrypted = Aes.Encrypt("Hola, Mundo!", key, iv);
string decrypted = Aes.Decrypt(encrypted, key, iv);

// Cifrar un arreglo de bytes
byte[] encryptedBytes = Aes.Encrypt(Encoding.UTF8.GetBytes("Hola, Mundo!"), key, iv);
byte[] decryptedBytes = Aes.Decrypt(encryptedBytes, key, iv);

Console.WriteLine($"Descifrado: {decrypted}");
```

### ⚡ **Cifrado ChaCha20-Poly1305**
Cifrado ligero y seguro con datos asociados (AAD):
```csharp
using SimpleEncryption.Encryption;

byte[] key = ChaCha20.GenerateKey("password", "salt");
byte[] nonce = ChaCha20.GenerateNonce();

// Cifrar una cadena
string encrypted = ChaCha20.Encrypt("Hola, Mundo!", key, nonce);
string decrypted = ChaCha20.Decrypt(encrypted, key, nonce);

// Cifrar un arreglo de bytes
byte[] encryptedBytes = ChaCha20.Encrypt(Encoding.UTF8.GetBytes("Hola, Mundo!"), key, nonce);
byte[] decryptedBytes = ChaCha20.Decrypt(encryptedBytes, key, nonce);

Console.WriteLine($"Descifrado: {decrypted}");
```

### 🔑 **Hashing (SHA-256 y SHA-512)**
Hashea cadenas de forma segura con o sin salt:
```csharp
using SimpleEncryption.Hashing;

// Hashear una cadena
string sha256Hash = Sha256.Hash("password");
string sha512Hash = Sha512.Hash("password");

// Hashear una cadena con salt
string sha256Salted = Sha256.Hash("password", "salt");
string sha512Salted = Sha512.Hash("password", "salt");

Console.WriteLine($"Hash SHA-256: {sha256Hash}");
Console.WriteLine($"Hash SHA-512: {sha512Hash}");
```

### 🧬 **Derivación de Claves PBKDF2**
Deriva claves seguras:
```csharp
using SimpleEncryption.Derivation;

byte[] salt = Encoding.UTF8.GetBytes("random_salt");

// Derivar una clave a partir de una contraseña
string derivedKey = Pbkdf2.DeriveKey("password", salt);
byte[] derivedKeyBytes = Pbkdf2.DeriveKey(Encoding.UTF8.GetBytes("password"), salt);

Console.WriteLine($"Clave Derivada: {derivedKey}");
```

---

## 🤝 Contribuciones
¡Las contribuciones son bienvenidas! No dudes en abrir un problema o enviar un pull request en [GitHub](https://github.com/Davimity/Simple/tree/main/SimpleEncryption).

---

## 🐝 Compatibilidad con SO
- **ChaCha20-Poly1305** **no es compatible** con:
  - `iOS`
  - `tvOS`
  - `entornos de navegador`
- **Cifrado AES** **no es compatible** con:
  - `entornos de navegador`

---

## 🐝 Licencia
Este proyecto está licenciado bajo la **Licencia MIT**.

## ⚠️ Seguridad y Exención de Responsabilidad

Esta biblioteca ha sido desarrollada con el objetivo de proporcionar la máxima seguridad posible en los algoritmos de cifrado, hashing y derivación de claves. Sin embargo:

- **No se garantiza** que la implementación esté completamente libre de vulnerabilidades.
- **El uso de esta biblioteca es bajo tu propia responsabilidad**.
- No se ofrece ninguna garantía sobre su idoneidad para aplicaciones críticas de seguridad o entornos altamente sensibles.

Si planeas usar esta biblioteca en un entorno de alta seguridad, se **recomienda encarecidamente** realizar auditorías de seguridad adicionales y seguir las mejores prácticas en criptografía.

