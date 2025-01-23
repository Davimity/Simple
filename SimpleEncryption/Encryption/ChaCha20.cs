using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;

namespace SimpleEncryption.Encryption {
    public class ChaCha20 {
        #region Variables

            public static int NonceSize { get; set; } = 12;

            public static HashAlgorithmName KeyDerivationAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        #endregion

        #region Public methods

            /// <summary>Encrypts a string using ChaCha20-Poly1305.</summary>
            /// <param name="input">String to encrypt.</param>
            /// <param name="key">Key of 32 bytes.</param>
            /// <param name="nonce">Nonce of 12 bytes.</param>
            /// <returns>Encrypted string in Base64 format.</returns>
            public static string Encrypt(string input, byte[] key, byte[] nonce, byte[]? associatedData = null) {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes (256 bits).", nameof(key));
                if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));

                var plainBytes = Encoding.UTF8.GetBytes(input);
                var cipherBytes = Encrypt(plainBytes, key, nonce, associatedData);

                return Convert.ToBase64String(cipherBytes);
            }

            /// <summary>Encrypts a byte array using ChaCha20-Poly1305.</summary>
            /// <param name="input">Array of bytes to encrypt.</param>
            /// <param name="key">Key of 32 bytes.</param>
            /// <param name="nonce">Nonce of 12 bytes.</param>
            /// <returns>Ecnrypted byte array.</returns>
            public static byte[] Encrypt(byte[] input, byte[] key, byte[] nonce, byte[]? associatedData = null) {
                if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes (256 bits).", nameof(key));
                if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes.", nameof(nonce));

                using (var cipher = new ChaCha20Poly1305(key)) {
                    var ciphertext = new byte[input.Length];
                    var tag = new byte[16];

                    cipher.Encrypt(nonce, input, ciphertext, tag, associatedData);

                    var result = new byte[nonce.Length + tag.Length + ciphertext.Length];
                    Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
                    Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
                    Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);

                    return result;
                }
            }

            /// <summary>Dencrypts a string using ChaCha20-Poly1305.</summary>
            /// <param name="input">String to decrypt.</param>
            /// <param name="key">Key of 32 bytes.</param>
            /// <returns>Decrypted string.</returns>
            public static string Decrypt(string input, byte[] key) {
                var cipherBytes = Convert.FromBase64String(input);
                var plainBytes = Decrypt(cipherBytes, key);
                return Encoding.UTF8.GetString(plainBytes);
            }

            /// <summary>Decrypts a byte array using ChaCha20-Poly1305.</summary>
            /// <param name="input">Message to decrypt.</param>
            /// <param name="key">Key of 32 bytes.</param>
            /// <returns>Dencrypted byte array.</returns>
            public static byte[] Decrypt(byte[] input, byte[] key) {
                if (input.Length == 0) return [];

                if (key == null || key.Length != 32) throw new ArgumentException("Key must be 32 bytes (256 bits).", nameof(key));
                if (input == null || input.Length < 28) throw new ArgumentException("invalid encrypted message", nameof(input));

                using (var cipher = new ChaCha20Poly1305(key)) {
                    var nonce = new byte[12];
                    var tag = new byte[16];
                    var ciphertextLength = input.Length - nonce.Length - tag.Length;
                    var ciphertext = new byte[ciphertextLength];

                    Buffer.BlockCopy(input, 0, nonce, 0, nonce.Length);
                    Buffer.BlockCopy(input, nonce.Length, tag, 0, tag.Length);
                    Buffer.BlockCopy(input, nonce.Length + tag.Length, ciphertext, 0, ciphertextLength);

                    var plaintext = new byte[ciphertextLength];

                    cipher.Decrypt(nonce, ciphertext, tag, plaintext);

                    return plaintext;
                }
            }


            /// <summary> Generates a 32-byte key for ChaCha20-Poly1305.</summary>
            /// <param name="input">Input to derive the key.</param>
            /// <param name="salt">Salt to derive the key.</param>
            /// <param name="iterations">Iterations to derive the key.</param>
            /// <returns>Ket of 32 bytes.</returns>
            public static byte[] GenerateKey(string input, string salt, int iterations = 100000) {
                var inputBytes = Encoding.UTF8.GetBytes(input);
                var saltBytes = Encoding.UTF8.GetBytes(salt);

                try {
                    using (var deriveBytes = new Rfc2898DeriveBytes(inputBytes, saltBytes, iterations, KeyDerivationAlgorithm)) {
                        return deriveBytes.GetBytes(32);
                    }
                }
                finally {
                    CryptographicOperations.ZeroMemory(inputBytes);
                    CryptographicOperations.ZeroMemory(saltBytes);
                }
            }

            /// <summary>Generates a 32-byte key for ChaCha20-Poly1305.</summary>
            /// <param name="input">Input to derive the key.</param>
            /// <param name="salt">Salt to derive the key.</param>
            /// <param name="iterations">Number of iterations to derive the key.</param>
            /// <param name="destroyInputs">True if the input and salt arrays should be destroyed after use.</param>
            /// <returns>Ket of 32 bytes.</returns>
            public static byte[] GenerateKey(byte[] input, byte[] salt, int iterations = 100000, bool destroyInputs = false) {
                try {
                    using (var deriveBytes = new Rfc2898DeriveBytes(input, salt, iterations, KeyDerivationAlgorithm)) {
                        return deriveBytes.GetBytes(32);
                    }
                }
                finally {
                    if (destroyInputs) {
                        CryptographicOperations.ZeroMemory(input);
                        CryptographicOperations.ZeroMemory(salt);
                    }
                }
            }


            /// <summary>Gnerates a 12-byte nonce for ChaCha20-Poly1305.</summary>
            /// <returns>Nonce of 12 bytes.</returns>
            public static byte[] GenerateNonce() {
                var nonce = new byte[NonceSize];
                using (var rng = RandomNumberGenerator.Create()) {
                    rng.GetBytes(nonce);
                }
                return nonce;
            }

            /// <summary>Generates a 12-byte nonce for ChaCha20-Poly1305.</summary>
            /// <param name="input">Input to derive the nonce.</param>
            /// <param name="salt">Salt to derive the nonce.</param>
            /// <param name="iterations">Iterations to derive the nonce.</param>
            /// <returns>Nonce of 12 bytes.</returns>
            public static byte[] GenerateNonce(string input, string salt, int iterations = 100000) {
                var inputBytes = Encoding.UTF8.GetBytes(input);
                var saltBytes = Encoding.UTF8.GetBytes(salt);

                try {
                    using (var deriveBytes = new Rfc2898DeriveBytes(inputBytes, saltBytes, iterations, KeyDerivationAlgorithm)) {
                        return deriveBytes.GetBytes(NonceSize);
                    }
                }
                finally {
                    CryptographicOperations.ZeroMemory(inputBytes);
                    CryptographicOperations.ZeroMemory(saltBytes);
                }
            }

            /// <summary>Gnerates a 12-byte nonce for ChaCha20-Poly1305.</summary>
            /// <param name="input">Input to derive the nonce.</param>
            /// <param name="salt">Salt to derive the nonce.</param>
            /// <param name="iterations">Number of iterations to derive the nonce.</param>
            /// <param name="destroyInputs">True if the input and salt arrays should be destroyed after use.</param>
            /// <returns>Nonce of 12 bytes.</returns>
            public static byte[] GenerateNonce(byte[] input, byte[] salt, int iterations = 100000, bool destroyInputs = false) {
                try {
                    using (var deriveBytes = new Rfc2898DeriveBytes(input, salt, iterations, KeyDerivationAlgorithm)) {
                        return deriveBytes.GetBytes(NonceSize);
                    }
                }
                finally {
                    if (destroyInputs) {
                        CryptographicOperations.ZeroMemory(input);
                        CryptographicOperations.ZeroMemory(salt);
                    }
                }
            }

        #endregion
    }
}
