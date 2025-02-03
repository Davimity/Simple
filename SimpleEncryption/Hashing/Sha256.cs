using System.Security.Cryptography;
using System.Text;

namespace SimpleEncryption.Hashing {
    ///<summary> Class for the Sha256 hashing algorithm </summary>
    ///<remarks> For null input, an exception will be thrown. </remarks>
    public class Sha256 {
        #region Variables

            private static readonly Sha256Algorithm _algorithm = new();

        #endregion

        #region Public Methods

            ///<summary> Hashes a string using SHA256 hashing </summary>
            ///<param name="input"> The string to hash </param>
            ///<param name="parameters"> The parameters to use </param>
            ///<returns> The hashed string </returns>
            public static string Hash(string input, Sha256HashParameters parameters) {
                if (input == null) throw new ArgumentNullException(nameof(input));

                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                var data = _algorithm.Hash(inputBytes, parameters);

                CryptographicOperations.ZeroMemory(inputBytes);

                var sb = new StringBuilder();
                foreach (var b in data) sb.Append(b.ToString("x2"));

                CryptographicOperations.ZeroMemory(data);

                return sb.ToString();
            }

            ///<summary> Hashes a string using SHA256 hashing </summary>
            ///<param name="input"> The string to hash </param>
            ///<param name="salt"> The salt to add </param>
            ///<returns> The hashed string </returns>
            public static string Hash(string input, string? salt = null) => Hash(input, new Sha256HashParameters { Salt = salt == null ? null : Encoding.UTF8.GetBytes(salt) });

            ///<summary> Hashes a byte array using SHA256 hashing </summary>
            ///<param name="input"> The byte array to hash </param>
            ///<param name="parameters"> The parameters to use </param>
            ///<returns> The hashed byte array </returns>
            public static byte[] Hash(byte[] input, Sha256HashParameters parameters) => _algorithm.Hash(input, parameters);

            ///<summary> Hashes a byte array using SHA256 hashing </summary>
            ///<param name="input"> The byte array to hash </param>
            ///<param name="salt"> The salt to add </param>
            ///<returns> The hashed byte array </returns>
            public static byte[] Hash(byte[] input, byte[]? salt = null) => Hash(input, new Sha256HashParameters { Salt = salt });

        #endregion
    }

    ///<summary> Parameters for the Sha256 hashing algorithm </summary>
    ///<remarks> Initially, salt is null. Use the dispose method to clear the data (salt will be set to null). </remarks>
    public class Sha256HashParameters : HashParameters {
        #region Parameters
                             
            public byte[]? Salt;

        #endregion

        #region Public methods

            public override void Dispose() {
                if(Salt != null) {
                    CryptographicOperations.ZeroMemory(Salt);
                    Salt = null;
                }
            }

        #endregion
    }

    ///<summary> Implementation of the Sha256 hashing algorithm </summary>
    ///<remarks> For null input, an exception will be thrown. </remarks>
    public class Sha256Algorithm : IHashAlgorithm, IDisposable {
        #region Variables

            private readonly SHA256 _Sha = SHA256.Create();

        #endregion

        #region Public methods

            public byte[] Hash(byte[] input, HashParameters parameters) {
                if(input == null) throw new ArgumentNullException(nameof(input));
                if (parameters is not Sha256HashParameters sha256Params) throw new ArgumentException("Parameters must be of type Sha256HashParameters.");

                var combined = new byte[input.Length + (sha256Params.Salt == null ? 0 : sha256Params.Salt.Length)];

                Buffer.BlockCopy(input, 0, combined, 0, input.Length);
                if(sha256Params.Salt != null) Buffer.BlockCopy(sha256Params.Salt, 0, combined, input.Length, sha256Params.Salt.Length);

                var data = _Sha.ComputeHash(combined);
                CryptographicOperations.ZeroMemory(combined);

                return data;       
            }

            public void Dispose() {
                _Sha.Dispose();
            }

        #endregion
    }
}
