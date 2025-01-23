using System.Security.Cryptography;
using System.Text;

namespace SimpleCryptography.Hashing {
    public class Sha512 {
        #region Variables

            private static readonly SHA512 Sha = SHA512.Create();

        #endregion

        #region Public Methods

            ///<summary> Hashes a string using SHA512 hashing </summary>
            ///<param name="input"> The string to hash </param>
            ///<returns> The hashed string </returns>
            public static string Hash(string input) {
                var data = Sha.ComputeHash(Encoding.UTF8.GetBytes(input));

                var sb = new StringBuilder();
                foreach (var b in data) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }

            ///<summary> Hashes a string using SHA512 hashing with salt </summary>
            ///<param name="input"> The string to hash </param>
            ///<param name="salt"> The salt to add </param>
            ///<returns> The hashed string </returns>
            public static string Hash(string input, string salt) {
                var saltedInput = Encoding.UTF8.GetBytes(input + salt);
                var data = Sha.ComputeHash(saltedInput);

                var sb = new StringBuilder();
                foreach (var b in data) sb.Append(b.ToString("x2"));

                return sb.ToString();
            }

            ///<summary> Hashes a byte array using SHA512 hashing </summary>
            ///<param name="input"> The byte array to hash </param>
            ///<param name="destroyArray"> If true, the input array will be destroyed after the operation </param>
            ///<returns> The hashed byte array </returns>
            public static byte[] Hash(byte[] input, bool destroyArray = false) {
                var data = Sha.ComputeHash(input);

                if (destroyArray) CryptographicOperations.ZeroMemory(input);
                return data;
            }

            ///<summary> Hashes a byte array using SHA512 hashing with salt </summary>
            ///<param name="input"> The byte array to hash </param>
            ///<param name="salt"> The salt to add </param>
            ///<param name="destroyArrays"> If true, the input and salt arrays will be destroyed after the operation </param>
            ///<returns> The hashed byte array </returns>
            public static byte[] Hash(byte[] input, byte[] salt, bool destroyArrays = false) {
                using (var sha512 = SHA512.Create()) {
                    var combined = new byte[input.Length + salt.Length];

                    Buffer.BlockCopy(input, 0, combined, 0, input.Length);
                    Buffer.BlockCopy(salt, 0, combined, input.Length, salt.Length);

                    var data = sha512.ComputeHash(combined);

                    CryptographicOperations.ZeroMemory(combined);

                    if (destroyArrays) {
                        CryptographicOperations.ZeroMemory(input);
                        CryptographicOperations.ZeroMemory(salt);
                    }

                    return data;
                }
            }

        #endregion
    }
}
