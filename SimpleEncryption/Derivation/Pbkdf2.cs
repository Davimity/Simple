using System.Security.Cryptography;
using System.Text;

using SimpleEncryption.Hashing;

namespace SimpleEncryption.Derivation {
    public class Pbkdf2 {
        #region Public methods

            /// <summary> Derives a key from a password and a salt. </summary>
            /// <param name="password"> Password to derive the key from. </param>
            /// <param name="salt"> Salt to use. </param>
            /// <param name="keySize"> Length of the key in bytes. </param>
            /// <param name="iterations"> Number of iterations to use. </param>
            /// <param name="hashAlgorithm"> Hash algorithm to use. </param>
            /// <returns> Derived key. </returns>
            public static string DeriveKey(string password, byte[] salt, int keySize = 32, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                keySize = keySize > 0 ? keySize : 32;
                iterations = iterations > 0 ? iterations : 100000;
                hashAlgorithm = hashAlgorithm != default ? hashAlgorithm : HashAlgorithmName.SHA256;
                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm);
                return Convert.ToBase64String(pbkdf2.GetBytes(keySize));
            }

            /// <summary> Derives a key from a password and a salt. </summary>
            /// <param name="password"> Password to derive the key from. </param>
            /// <param name="salt"> Salt to use. </param>
            /// <param name="keySize"> Length of the key in bytes. </param>
            /// <param name="iterations"> Number of iterations to use. </param>
            /// <param name="hashAlgorithm"> Hash algorithm to use. </param>
            /// <returns> Derived key. </returns>
            public static byte[] DeriveKey(byte[] password, byte[] salt, int keySize = 32, int iterations = 100000, HashAlgorithmName hashAlgorithm = default) {
                keySize = keySize > 0 ? keySize : 32;
                iterations = iterations > 0 ? iterations : 100000;
                hashAlgorithm = hashAlgorithm != default ? hashAlgorithm : HashAlgorithmName.SHA256;
                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm);
                return pbkdf2.GetBytes(keySize);
            }

            /// <summary> Generates a cryptographic salt of the specified size. </summary>
            /// <param name="size"> The size of the salt in bytes. </param>
            /// <returns> A randomly generated salt. </returns>
            public static byte[] GenerateSalt(int size = 32) {
                size = size > 0 ? size : 32;
                var salt = new byte[size];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(salt);
                return salt;
            }

            /// <summary> Generates a cryptographic salt from the input. </summary>
            /// <param name="input"> The input to generate the salt from. </param>
            /// <param name="size"> The size of the salt in bytes. </param>
            /// <returns> A salt generated from the input. </returns>
            public static byte[] GenerateSalt(string input, int size = 32) {
                size = size > 0 ? size : 32;
                byte[] hash = Encoding.UTF8.GetBytes(Sha512.Hash(input));
                byte[] saltBytes = new byte[size];
                Array.Copy(hash, saltBytes, size);

                return saltBytes;
            }

            /// <summary> Generates a cryptographic salt from the input. </summary>
            /// <param name="input"> The input to generate the salt from. </param>
            /// <param name="size"> The size of the salt in bytes. </param>
            /// <returns> A salt generated from the input. </returns>
            public static byte[] GenerateSalt(byte[] input, int size = 32) {
                size = size > 0 ? size : 32;
                byte[] hash = Sha512.Hash(input);
                byte[] saltBytes = new byte[size];
                Array.Copy(hash, saltBytes, size);

                return saltBytes;
            }

        #endregion
    }
}
