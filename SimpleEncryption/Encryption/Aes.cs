using System.Security.Cryptography;
using System.Text;

using SAes = System.Security.Cryptography.Aes;

namespace SimpleEncryption.Encryption {
    public class Aes {
        #region Variables

            private static readonly ThreadLocal<SAes> AesInstance = new(SAes.Create);

        #endregion

        #region Public methods

            /// <summary> Encrypts a string using AES encryption </summary>
            /// <param name="input"> The string to encrypt </param>
            /// <param name="key"> The key. Length must be 32 bytes (256 bits) </param>
            /// <param name="iv"> The initialization vector. Length must be 16 bytes </param>
            /// <returns> The encrypted string </returns>
            public static string Encrypt(string input, byte[] key, byte[] iv) {
                var aes = GetAesInstance();

                aes.Key = key;
                aes.IV = iv;

                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (var ms = new MemoryStream()) {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {
                        using (var sw = new StreamWriter(cs)) {
                            sw.Write(input);
                        }
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }

            /// <summary> Encrypts a byte array using AES encryption </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="key"> The key. Length must be 32 bytes (256 bits) </param>
            /// <param name="iv"> The initialization vector. Length must be 16 bytes </param>
            /// <returns> The encrypted byte array </returns>
            public static byte[] Encrypt(byte[] input, byte[] key, byte[] iv) {
                var aes = GetAesInstance();

                aes.Key = key;
                aes.IV = iv;

                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (var ms = new MemoryStream()) {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {
                        cs.Write(input, 0, input.Length);
                        cs.FlushFinalBlock();
                    }

                    return ms.ToArray();
                }
            }

            /// <summary> Decrypts a string using AES encryption </summary>
            /// <param name="input"> The string to decrypt </param>
            /// <param name="key"> The initialization vector. Length must be 16 bytes </param>
            /// <param name="iv"> The key. Length must be 32 bytes (256 bits) </param>
            /// <return> The decrypted string </return>
            public static string Decrypt(string input, byte[] key, byte[] iv) {
                if (string.IsNullOrEmpty(input)) return string.Empty;

                var aes = GetAesInstance();

                aes.Key = key;
                aes.IV = iv;

                var decryptor = aes.CreateDecryptor();
                using (var ms = new MemoryStream(Convert.FromBase64String(input))) {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {
                        using (var sr = new StreamReader(cs)) {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }

            /// <summary> Decrypts a byte array using AES encryption </summary>
            /// <param name="input"> The byte array to encrypt </param>
            /// <param name="key"> The initialization vector. Length must be 16 bytes </param>
            /// <param name="iv"> The key. Length must be 32 bytes (256 bits) </param>
            /// <returns> The decrypted byte array </returns>
            public static byte[] Decrypt(byte[] input, byte[] key, byte[] iv) {
                if (input.Length == 0) return [];

                var aes = GetAesInstance();

                aes.Key = key;
                aes.IV = iv;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream(input)) {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {
                        using (var msOut = new MemoryStream()) {
                            cs.CopyTo(msOut);
                            return msOut.ToArray();
                        }
                    }
                }
            }


            /// <summary> Generates a key for AES encryption </summary>
            /// <param name="input"> The input string </param>
            /// <param name="salt"> The salt string </param>
            /// <param name="iterations"> The number of iterations to generate the key </param>
            /// <returns> The generated key </returns>
            public static byte[] GenerateKey(string input, string salt, int iterations = 0) {
                var bSalt = Encoding.UTF8.GetBytes(salt);

                try {
                    var rinput = SimpleEncryption.Hashing.Sha512.Hash(input, salt);

                    if (iterations <= 0) {
                        using (var sha = SHA256.Create()) {
                            var hash = sha.ComputeHash(bSalt);
                            iterations = BitConverter.ToInt32(hash, 0) & 0x7FFFFFFF;
                            iterations = 10000 + (iterations % 90000);
                        }
                    }

                    using (var deriveBytes = new Rfc2898DeriveBytes(rinput, bSalt, iterations, HashAlgorithmName.SHA512)) {
                        return deriveBytes.GetBytes(GetAesInstance().KeySize / 8);
                    }
                }
                finally {
                    CryptographicOperations.ZeroMemory(bSalt);
                }
            }

            /// <summary> Generates a key for AES encryption </summary>
            /// <param name="input"> The input byte[] </param>
            /// <param name="salt"> The salt byte[] </param>
            /// <param name="iterations"> The number of iterations to generate the key </param>
            /// <param name="destroyInputs"> True to destroy input and salt arrays after use </param>
            /// <returns> The generated key </returns>
            public static byte[] GenerateKey(byte[] input, byte[] salt, int iterations = 0, bool destroyInputs = false) {
                try {
                    var rinput = SimpleEncryption.Hashing.Sha512.Hash(input, salt);

                    if (iterations <= 0) {
                        using (var sha = SHA256.Create()) {
                            var hash = sha.ComputeHash(salt);
                            iterations = BitConverter.ToInt32(hash, 0) & 0x7FFFFFFF;
                            iterations = 10000 + (iterations % 90000);
                        }
                    }

                    using (var deriveBytes = new Rfc2898DeriveBytes(rinput, salt, iterations, HashAlgorithmName.SHA512)) {
                        return deriveBytes.GetBytes(GetAesInstance().KeySize / 8);
                    }
                }
                finally {
                    if (destroyInputs) {
                        CryptographicOperations.ZeroMemory(input);
                        CryptographicOperations.ZeroMemory(salt);
                    }
                }
            }

            /// <summary> Generates an initialization vector for AES encryption </summary>
            /// <param name="input"> The input string </param>
            /// <param name="salt"> The salt string </param>
            /// <param name="iterations"> The number of iterations to generate the IV </param>
            /// <returns> The generated IV </returns>
            public static byte[] GenerateIv(string input, string salt, int iterations = 0) {
                var bSalt = Encoding.UTF8.GetBytes(salt);

                try {
                    var rinput = SimpleEncryption.Hashing.Sha512.Hash(input, salt);

                    if (iterations <= 0) {
                        using (var sha = SHA256.Create()) {
                            var hash = sha.ComputeHash(bSalt);
                            iterations = BitConverter.ToInt32(hash, 0) & 0x7FFFFFFF;
                            iterations = 10000 + (iterations % 90000);
                        }
                    }

                    using (var deriveBytes = new Rfc2898DeriveBytes(rinput, bSalt, iterations, HashAlgorithmName.SHA512)) {
                        return deriveBytes.GetBytes(16);
                    }
                }
                finally {
                    CryptographicOperations.ZeroMemory(bSalt);
                }
            }

            /// <summary> Generates an initialization vector for AES encryption </summary>
            /// <param name="input"> The input byte[] </param>
            /// <param name="salt"> The salt byte[] </param>
            /// <param name="iterations"> The number of iterations to generate the IV </param>
            /// <param name="destroyInputs"> True to destroy input and salt arrays after use </param>
            /// <returns> The generated IV </returns>
            public static byte[] GenerateIv(byte[] input, byte[] salt, int iterations = 0, bool destroyInputs = false) {
                try {
                    var rinput = SimpleEncryption.Hashing.Sha512.Hash(input, salt);

                    if (iterations <= 0) {
                        using (var sha = SHA256.Create()) {
                            var hash = sha.ComputeHash(salt);
                            iterations = BitConverter.ToInt32(hash, 0) & 0x7FFFFFFF;
                            iterations = 10000 + (iterations % 90000);
                        }
                    }

                    using (var deriveBytes = new Rfc2898DeriveBytes(rinput, salt, iterations, HashAlgorithmName.SHA512)) {
                        return deriveBytes.GetBytes(16);
                    }
                }
                finally {
                    if (destroyInputs) {
                        CryptographicOperations.ZeroMemory(input);
                        CryptographicOperations.ZeroMemory(salt);
                    }
                }
            }


            /// <summary> Modifies the AES cipher mode for the current thread </summary>
            /// <param name="mode"> The new cipher mode </param>
            public static void ModifyCipherMode(CipherMode mode) => GetAesInstance().Mode = mode;

            /// <summary> Modifies the AES padding mode for the current thread </summary>
            /// <param name="mode"> The new padding mode </param>
            public static void ModifyPadding(PaddingMode mode) => GetAesInstance().Padding = mode;

            /// <summary> Modifies the AES block size for the current thread </summary>
            /// <param name="size"> The new block size in bits </param>
            public static void ModifyBlockSize(int size) => GetAesInstance().BlockSize = size;

            /// <summary> Modifies the AES key size for the current thread </summary>
            /// <param name="size"> The new key size in bits </param>
            public static void ModifyKeySize(int size) => GetAesInstance().KeySize = size;

            ///<summary> Disposes the AES instance for the current thread </summary>
            ///<remarks> This method should be called when the AES instance is no longer needed for the current thread </remarks>
            public static void Dispose() {
                GetAesInstance().Dispose();
            }

        #endregion

        #region Private Methods

            /// <summary> Ensures that the AES instance is not null </summary>
            /// <returns> The AES instance </returns>
            private static SAes GetAesInstance() {
                return AesInstance.Value ?? throw new NullReferenceException("AES instance is not initialized.");
            }

        #endregion
    }
}
