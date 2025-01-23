using System.Security.Cryptography;
using System.Text;

using SimpleEncryption.Hashing;

using a2id = Konscious.Security.Cryptography.Argon2id;

namespace SimpleEncryption.Derivation.Argon2 {
    public class Argon2id {
        #region Public methods

            /// <summary> Derives a key from a password and a salt. </summary>
            /// <param name="password"> Password to derive the key from. </param>
            /// <param name="salt"> Salt to use. </param>
            /// <param name="keyLength"> Length of the key in bytes. </param>
            /// <param name="iterations"> Number of iterations to use. </param>
            /// <param name="memory"> Memory to use. </param>
            /// <param name="threads"> Number of threads to use. </param>
            /// <returns> Derived key. </returns>
            public static string DeriveKey(string password, string salt, int keyLength = 64, int iterations = 10, int memory = 262144, int threads = 4) {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

                using (var argon2 = new a2id(passwordBytes)) {
                    argon2.Salt = saltBytes;
                    argon2.DegreeOfParallelism = threads;
                    argon2.MemorySize = memory;
                    argon2.Iterations = iterations;

                    byte[] _b = argon2.GetBytes(keyLength);

                    var sb = new StringBuilder();
                    foreach (var b in _b) sb.Append(b.ToString("x2"));

                    CryptographicOperations.ZeroMemory(_b);

                    return sb.ToString();
                }
            }

            /// <summary> Derives a key from a password and a salt. </summary>
            /// <param name="password"> Password to derive the key from. </param>
            /// <param name="salt"> Salt to use. </param>
            /// <param name="keyLength"> Length of the key in bytes. </param>
            /// <param name="iterations"> Number of iterations to use. </param>
            /// <param name="memory"> Memory to use. </param>
            /// <param name="threads"> Number of threads to use. </param>
            /// <returns> Derived key. </returns>
            public static byte[] DeriveKey(byte[] password, byte[] salt, int keyLength = 64, int iterations = 10, int memory = 262144, int threads = 4) {
                using (var argon2 = new a2id(password)) {
                    argon2.Salt = salt;
                    argon2.DegreeOfParallelism = threads;
                    argon2.MemorySize = memory;
                    argon2.Iterations = iterations;

                    return argon2.GetBytes(keyLength);
                }
            }

            /// <summary> Generates a salt </summary>
            /// <param name="input">Input to generate the salt from.</param>
            /// <param name="length">Length of the salt.</param>
            /// <returns> Salt of the specified length. </returns>
            public static string GenerateSalt(string input, int length) {
                byte[] hash = Sha512.Hash(Encoding.UTF8.GetBytes(input));
                byte[] saltBytes = new byte[length];
                Array.Copy(hash, saltBytes, length);

                return Convert.ToBase64String(saltBytes);
            }

            /// <summary> Generates a salt </summary>
            /// <param name="input"> Input to generate the salt from. </param>
            /// <param name="length"> Length of the salt. </param>
            /// <returns> Salt of the specified length. </returns>
            public static byte[] GenerateSalt(byte[] input, int length) {
                byte[] hash = Sha512.Hash(input);
                byte[] saltBytes = new byte[length];
                Array.Copy(hash, saltBytes, length);

                return saltBytes;
            }

        #endregion
    }
}
